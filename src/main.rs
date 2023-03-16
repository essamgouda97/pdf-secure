// TODO Error handling
// TODO Handle windows and linux paths
// TODO security on all saved files
// TODO script to autogenerate key and nonce

use std::{
    str,
    process,
    path::Path,
    fs::{self, File, read_to_string}, 
    collections::{HashMap, HashSet},
};

use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream, Aead, NewAead},
    XChaCha20Poly1305,
};
use serde::{Serialize, Deserialize};
use serde_json;
use pdfium_render::prelude::*;
use show_image::{create_window, event};
use glob::glob;

// Constansts
const BIN_PATH: &str = ".\\bin\\";
const FILES_PATH: &str = ".\\Files";
const USB_ID_FILE: &str = "./System Volume Information/IndexerVolumeGuid";
const KEY: [u8; 32] = [201, 246, 255, 188, 110, 230, 
                    94, 198, 192, 77, 164, 20, 5, 122, 
                    116, 209, 113, 208, 241, 175, 251, 
                    52, 138, 202, 197, 204, 234, 230, 
                    120, 164, 160, 52];
const NONCE: [u8; 24] =  [213, 85, 53, 54, 40, 196, 
                        219, 239, 120, 62, 63, 205, 
                        43, 146, 64, 252, 128, 242, 
                        103, 225, 59, 7, 43, 130];
const INDEX_CHAR: &str = "@@";
const IMAGES_PREFIX: &str = "_@@.enc";

#[derive(Serialize, Deserialize, Debug)]
struct MetaData {
    file_open_count: i8, // number of times file is opened
    max_files_open_count: i8, // maximum number of times a file is allowed to be opened
    renders_config: HashMap<usize, (u32, u32)>,
    glob_pattern: String,
    number_of_images: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct DB {
    usb_id: String, 
    data: HashMap<String, MetaData>
}

impl DB {
    fn new(usb_id: &String) -> DB {
        DB {
            usb_id: usb_id.to_string(),
            data: HashMap::new(),
        }
    }

    // Used to add new data
    fn join(
        &mut self,
        key: &str,
        value: MetaData,
        ){
            self.data.insert(key.to_string(), value);
    }

    // Used to update an existing entry
    fn update_file_open_count(
        &mut self,
        key: &str,
        file_open_count: i8,
    ) {
        if let Some(metadata) = self.data.get_mut(key) {
            metadata.file_open_count = file_open_count;
        }
    }
}


fn get_usb_id() -> String{ 
   let content = match read_to_string(USB_ID_FILE){
    Result::Ok(value) => value,
    Result::Err(error) => panic!("Couldn't open {} due to {}", USB_ID_FILE, error)
   };

   return content;
}

fn export_pdf_to_jpegs(path: &str, password: Option<&str>) -> Result<(HashMap<usize, (u32, u32)>, i32), PdfiumError> {
    // Renders each page in the PDF file at the given path to a separate JPEG file.

    // Bind to a Pdfium library in the same directory as our Rust executable;
    // failing that, fall back to using a Pdfium library provided by the operating system.
    println!("Creating pdf obj");
    let pdfium = Pdfium::new(
        Pdfium::bind_to_library(Pdfium::pdfium_platform_library_name_at_path(BIN_PATH))
        .or_else(|_| Pdfium::bind_to_system_library())?,
        );

    // Load the document from the given path...
    println!("Loading pdf document from {}", path);
    let document = pdfium.load_pdf_from_file(path, password).expect("Can't open pdf file");

    // ... set rendering options that will be applied to all pages...
    println!("Rendering pdf");
    let render_config = PdfRenderConfig::new()
        .set_target_width(2000)
        .set_maximum_height(2000)
        .rotate_if_landscape(PdfBitmapRotation::Degrees90, true);
    
    let cipher = XChaCha20Poly1305::new(&KEY.into());

    // ... then render each page to a bitmap image, saving each image to a JPEG file.
    let mut render_config_data = HashMap::new();
    let mut pages_num: i32 = 0;
    for (index, page) in document.pages().iter().enumerate() {
        let temp = page
            .render_with_config(&render_config)
            .unwrap()
            .as_image()
            .as_rgba8()
            .unwrap()
            .clone();

        let (x, y) = temp.dimensions();
        render_config_data.insert(index, (x,y));
        println!("{}:{}", x, y);
        println!("Encrypting {}", index);
        let encrypted_data = cipher
            .encrypt(&NONCE.into(), temp.into_raw().as_ref())
            .unwrap();
        let prefix_image = IMAGES_PREFIX.replace(INDEX_CHAR, index.to_string().as_str());
        fs::write(format!("{}{}", path, prefix_image), encrypted_data);
        pages_num+=1;
    }

    Ok((render_config_data, pages_num))
}

fn encrypt_mode(usb_id: &String) -> Result<(), anyhow::Error>{
   
    let paths = fs::read_dir(FILES_PATH)?;
    let cipher = XChaCha20Poly1305::new(&KEY.into());
    
    // Main encrypt loop
    let mut db = DB::new(usb_id); 

    for path in paths{
        
        // Encrypt pdf files
        let p = path.unwrap().path().into_os_string().into_string().unwrap();
        let filename = p.clone(); 
        // skip if file isn't pdf
        if ! p.ends_with(".pdf"){continue;};
       
        let file_data = fs::read(&p)?;
        println!("Converting {} to jpegs", filename); 
        let (renders_config, pages_num) = export_pdf_to_jpegs(&filename, None).unwrap();
        fs::remove_file(p)?; // remove pdf
    
        // Ask user for number of times for file
        println!("What's the maximum number of time is {} allowed to be opened", filename);
        let mut max_number_open = String::new();
        std::io::stdin().read_line(&mut max_number_open).expect("Failed to read line");
        let max_number_open: i8 = max_number_open.trim().parse().expect("Please enter a positive number");        
        
        // Save to db 
        let db_data = MetaData{
            file_open_count: 1,
            max_files_open_count: max_number_open,
            renders_config: renders_config,
            glob_pattern: format!("{}{}", filename, IMAGES_PREFIX),
            number_of_images: pages_num,
        };
        db.join(&filename, db_data);         
    

    // Save db.json
    let mut db_file = File::create("db.json").expect("Failed to create db.json");
    let db = serde_json::to_string(&db).unwrap();
    let encrypted_db = cipher
        .encrypt(&NONCE.into(), db.as_ref())
        .map_err(|err| anyhow!("Ecrypting db: {}", err))?;
    fs::write("db.json", encrypted_db)?;  

    }

    Ok(())
}
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

fn decrypt_mode(usb_id: &String) -> Result<(), anyhow::Error>{

    let paths = fs::read_dir(".\\Files")?;
    let cipher = XChaCha20Poly1305::new(&KEY.into());

    // Read db.json
    let db_data_encrypted = fs::read("db.json").expect("db.json not found, make sure to run encrypt mode");
    let db_data_decrypted = cipher
        .decrypt(&NONCE.into(), db_data_encrypted.as_ref())
        .map_err(|err| anyhow!("Decrypting db: {}", err))?;
    
    let db_data_decoded = match str::from_utf8(&db_data_decrypted) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };
    let mut db_data: DB = serde_json::from_str(db_data_decoded).unwrap();

    // Confirm usb_id
    let current_usb_id = get_usb_id();
    if db_data.usb_id != current_usb_id{
        println!("pdf-secure can only run on the same usb device. {} != {}", db_data.usb_id, current_usb_id);
        process::exit(0);
    }

    // Ask user which file to view
    // TODO loop through db_data for all keys and ask user which file do they want to view

    // read files in db.json
    loop{

        // Show files to user
        let mut selected_file = String::new();
        let mut available_inputs: HashSet<String> = db_data.data
            .iter()
            .enumerate()
            .map(|(i, _)| i.to_string())
            .collect();

        println!("\n\nWhich file do you want to view? Type q to exit\n");
        let mut filenames: HashMap<String, String> = HashMap::new();
        let max_index = db_data.data.len();
        for (index, (key, _)) in db_data.data.iter().enumerate(){
            let index_display = index + 1;
            let filename_display =  key.split('\\').last().unwrap();
            println!("{}-  {}", index_display,filename_display);
            let index_str = index_display.to_string();
            filenames.insert(index_str, key.clone());
        }

        std::io::stdin().read_line(&mut selected_file).unwrap();
        let selected_file = selected_file.trim();
        if selected_file.parse::<usize>().unwrap() > max_index{
            println!("{} is not a valid input", selected_file);
            continue;
        }
        // Check if the input is "q"
        if selected_file == "q" {
            break;
        }

        // Check if the input is in available_inputs
        if available_inputs.contains(selected_file) {
            let filename = filenames.get(selected_file).unwrap();
            let filename_display =  filename.split('\\').last().unwrap();
            let mut file_metadata: &MetaData = db_data.data.get(filename).unwrap();

            // Check if file is allowed to be opened
            if file_metadata.file_open_count > file_metadata.max_files_open_count{
                println!("{} can't be opened anymore", filename_display);
                continue;
            }
            
            // view file
            let mut index: usize = 0;
            let current_image = read_image(filename, index, file_metadata).unwrap();
            let max_pages = file_metadata.number_of_images;

            // view image
            let window = create_window("Secure PDF Viewer", Default::default())
                .expect("Failed to create window");
            window.set_image(format!("Page {}/{}", index+1, max_pages), current_image)
                .expect("Failed to set image");
    
            for event in window.event_channel()? {
                if let event::WindowEvent::KeyboardInput(event) = event {
                    if event.input.key_code == Some(event::VirtualKeyCode::Escape) 
                        && event.input.state.is_pressed() {
                        break;
                    }
                    if event.input.key_code == Some(event::VirtualKeyCode::Right) 
                        && event.input.state.is_pressed() 
                        && index+1 < max_pages as usize{
                            index+=1;
                            let current_image = read_image(filename, index, file_metadata)
                                .unwrap();
                            window.set_image(format!("Page {}/{}", index+1, max_pages),current_image)
                                .expect("Failed to set image");
                    }
                    if event.input.key_code == Some(event::VirtualKeyCode::Left) 
                        && event.input.state.is_pressed() && index > 0{
                            index-=1;
                            let current_image = read_image(filename, index, file_metadata).unwrap();
                            window.set_image(format!("Page {}/{}", index+1, max_pages), current_image)
                                .expect("Failed to set image");
                    }
                }
            }
            // Update, save db.json
            db_data.update_file_open_count(filename, file_metadata.file_open_count+1);
            let mut db_file = File::create("db.json").expect("Failed to create db.json");
            let db = serde_json::to_string(&db_data).unwrap();
            let encrypted_db = cipher
                .encrypt(&NONCE.into(), db.as_ref())
                .map_err(|err| anyhow!("Ecrypting db: {}", err))?;
            fs::write("db.json", encrypted_db)?;  
        } else {
            println!("Please pick a valid file from the options, try again !");
            continue;
        }
    }

    Ok(())
}


fn read_image(filename: &str, index: usize, file_metadata: &MetaData) -> Result<image::DynamicImage, anyhow::Error>{
    

    let cipher = XChaCha20Poly1305::new(&KEY.into());
    let prefix_image = IMAGES_PREFIX.replace(INDEX_CHAR, index.to_string().as_str());
    let data_encrypted= fs::read(format!("{}{}", filename, prefix_image)).expect("Couldn't read pdf file");
    let rgba_data: Vec<u8> = cipher
        .decrypt(&NONCE.into(), data_encrypted.as_ref())
        .map_err(|err| anyhow!("Decrypting pdf: {}", err))?;
   

    let (x,y) = file_metadata.renders_config.get(&index).unwrap();
    let image_buffer: image::RgbImage = image::RgbImage::new(*x, *y);
    let mut pixel_data  = image_buffer.into_raw();

    for i in 0..rgba_data.len() / 4 {
        let r = rgba_data[i * 4];
        let g = rgba_data[i * 4 + 1];
        let b = rgba_data[i * 4 + 2];
        pixel_data[i * 3] = r;
        pixel_data[i * 3 + 1] = g;
        pixel_data[i * 3 + 2] = b;
    }


    let image_buffer =  image::RgbImage::from_raw(*x, *y, pixel_data).unwrap();
    let dynamic_image = image::DynamicImage::ImageRgb8(image_buffer);
    
    Ok(dynamic_image)
}

#[show_image::main]
fn main() {
    println!("Welcome to pdf-secure, a tool to secure your pdf files");
    
    // Check if program runs on a USB stick
    if Path::new(USB_ID_FILE).exists() {
        println!("USB device detected");        
    } else {
        println!("pdf-secure runs only on a USB device, Exiting");
        process::exit(0);
    }

    let usb_id: String = get_usb_id();


    println!("Which mode do you want to select?");
    println!("1. Setup USB device");
    println!("2. View PDF files");
    
    // Select mode
    let mut mode = String::new();
    std::io::stdin().read_line(&mut mode).expect("Failed to read line");

    let mode: u8 = mode.trim().parse().expect("Please type a number!");
    
    if mode == 1 {
        let result = encrypt_mode(&usb_id).unwrap();
    } else if mode == 2 {
        let result = decrypt_mode(&usb_id).unwrap();
    } else {
        println!("Invalid mode selected");
    }
}
