use std::{
    str,
    io::Read,
    fs::{File, read_to_string}, 
    collections::HashMap,
};

use serde::{Serialize, Deserialize};
use hex;

// Constansts
pub const BIN_PATH: &str = ".\\bin\\";
pub const FILES_PATH: &str = ".\\Files";
pub const USB_ID_FILE: &str = "./System Volume Information/IndexerVolumeGuid";
pub const INDEX_CHAR: &str = "@@";
pub const IMAGES_PREFIX: &str = "_@@.enc";

#### PLACE KEY AND NONCE HERE ####

#[derive(Serialize, Deserialize, Debug)]
pub struct MetaData {
    pub file_open_count: i8, // number of times file is opened
    pub max_files_open_count: i8, // maximum number of times a file is allowed to be opened
    pub renders_config: HashMap<usize, (u32, u32)>,
    pub glob_pattern: String,
    pub number_of_images: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DB {
    pub usb_id: String, 
    pub data: HashMap<String, MetaData>
}

impl DB {
    pub fn new(usb_id: &String) -> DB {
        DB {
            usb_id: usb_id.to_string(),
            data: HashMap::new(),
        }
    }

    // Used to add new data
    pub fn join(
        &mut self,
        key: &str,
        value: MetaData,
        ){
            self.data.insert(key.to_string(), value);
    }

    // Used to update an existing entry
    pub fn update_file_open_count(
        &mut self,
        key: &str,
        file_open_count: i8,
    ) {
        if let Some(metadata) = self.data.get_mut(key) {
            metadata.file_open_count = file_open_count;
        }
    }
}

pub fn get_usb_id() -> String{ 
    let content = match read_to_string(USB_ID_FILE){
     Result::Ok(value) => value,
     Result::Err(error) => panic!("Couldn't open {} due to {}", USB_ID_FILE, error)
    };
 
    return content;
 }

pub fn read_key_and_nonce() -> ([u8; 32], [u8; 24]) {
    let mut file = File::open("key_and_nonce.txt").expect("Unable to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Unable to read file");

    let key = hex::decode(&contents[0..64]).unwrap();
    let nonce = hex::decode(&contents[64..]).unwrap();

    let mut key_arr: [u8; 32] = [0; 32];
    let mut nonce_arr: [u8; 24] = [0; 24];

    for i in 0..32 {
        key_arr[i] = key[i];
    }

    for i in 0..24 {
        nonce_arr[i] = nonce[i];
    }

    (key_arr, nonce_arr)
}
