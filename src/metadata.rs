use node::Prefix;
use net::{Group, Groups};
use std::io::{self, Write};
use std::fs::File;
use std::path::Path;
use rustc_serialize::json::as_json;
use std::collections::HashMap;
use attack::most_malicious_groups;
use rustc_serialize::{Encodable};

#[derive(RustcEncodable)]
pub struct Data<T: Encodable> {
    name: String,
    yaxis: String,
    write_out: bool,
    x: Vec<usize>,
    y: Vec<T>,
}

pub struct Metadata {
    step_num: usize,
    num_sections: Data<usize>,
    num_nodes: Data<usize>,
    num_malicious: Data<usize>,
    most_malicious: Data<f64>,
    section_info: SectionInfo,
}

impl Metadata {
    pub fn new() -> Self {
        Metadata {
            step_num: 0,
            num_sections: Data::new("num_sections", "y"),
            num_nodes: Data::new("num_nodes", "y2"),
            num_malicious: Data::new("num_malicious", "y2"),
            most_malicious: Data::new("most_malicious", "y"),
            section_info: SectionInfo::new(),
        }
    }

    pub fn update(&mut self, groups: &Groups) {
        self.num_sections.add_point(self.step_num, groups.len());
        self.num_nodes.add_point(self.step_num, count_nodes(groups));
        self.num_malicious.add_point(self.step_num, num_malicious_total(groups));
        self.update_most_malicious(groups);
        self.section_info.update(self.step_num, groups);
        self.step_num += 1;
    }

    fn update_most_malicious(&mut self, groups: &Groups) {
        let malicious = most_malicious_groups(groups);
        let (_prefix, frac) = malicious[0];
        self.most_malicious.add_point(self.step_num, frac);
    }
}

impl <T: Encodable> Drop for Data<T> {
    fn drop(&mut self) {
        if self.write_out {
            if let Err(e) = self.write_out() {
                println!("Error while writing out: {:?}", e);
            }
        }
    }
}

impl <T: Encodable> Data<T> {
    pub fn new(name: &str, yaxis: &str) -> Self {
        Data {
            name: name.into(),
            x: vec![],
            y: vec![],
            yaxis: yaxis.into(),
            write_out: true
        }
    }

    pub fn add_point(&mut self, x: usize, y: T) {
        self.x.push(x);
        self.y.push(y);
    }

    pub fn write_out(&self) -> io::Result<()>{
        let mut f = open_file(&self.name)?;
        write!(f, "{}", as_json(self))
    }
}

fn count_nodes(groups: &Groups) -> usize {
    groups.values().map(|group| group.len()).sum()
}

fn open_file(name: &str) -> io::Result<File> {
    File::create(Path::new("viz").join(name.to_string() + ".json"))
}

pub struct SectionInfo {
    sections: HashMap<Prefix, Data<usize>>,
    malicious: HashMap<Prefix, Data<usize>>
}

impl SectionInfo {
    pub fn new() -> Self {
        SectionInfo {
            sections: HashMap::new(),
            malicious: HashMap::new()
        }
    }

    pub fn update(&mut self, step_num: usize, groups: &Groups) {
        for (prefix, group) in groups {
            let data_name = format!("{:?}", prefix).to_lowercase();
            let mut section_data = self.sections.entry(*prefix).or_insert_with(|| {
                Data::new(&data_name, "y")
            });
            let mut malicious_data = self.malicious.entry(*prefix).or_insert_with(|| {
                let trace_name = data_name.clone() + "_malicious";
                Data::new(&trace_name, "y")
            });

            section_data.add_point(step_num, group.len());
            malicious_data.add_point(step_num, num_malicious(group));
        }
    }
}

impl Drop for SectionInfo {
    fn drop(&mut self) {
        let size_data = extract_data(&mut self.sections);
        let malicious_data = extract_data(&mut self.malicious);

        if let Err(e) = write_out_array("section_sizes", size_data).and(
                        write_out_array("section_mal", malicious_data)) {
            println!("Something's fucked: {:?}", e);
        }
    }
}

fn extract_data<T: Encodable>(data_map: &mut HashMap<Prefix, Data<T>>) -> Vec<Data<T>> {
    data_map.drain().map(|(_, mut item)| {
        item.write_out = false;
        item
    }).collect()
}

fn write_out_array<T: Encodable>(name: &str, data: Vec<Data<T>>) -> io::Result<()> {
    let f = open_file(name)?;
    write!(&f, "{}", as_json(&data))
}

fn num_malicious_total(groups: &Groups) -> usize {
    groups.values().map(|g| num_malicious(g)).sum()
}

fn num_malicious(group: &Group) -> usize {
    group.values().filter(|n| n.is_malicious()).count()
}
