use node::Prefix;
use net::{Group, Groups, Network};
use std::io::{self, Write};
use std::fs::{File, create_dir_all};
use std::path::{Path, PathBuf};
use rustc_serialize::json::as_json;
use std::collections::HashMap;
use attack::most_malicious_groups;
use rustc_serialize::{Encodable};

#[derive(RustcEncodable, Clone)]
pub struct Data<T: Encodable> {
    dir: PathBuf,
    name: String,
    yaxis: String,
    pub write_out: bool,
    x: Vec<usize>,
    y: Vec<T>,
}

pub struct Metadata {
    step_num: usize,
    num_sections: Data<usize>,
    num_nodes: Data<usize>,
    num_malicious: Data<usize>,
    most_malicious: Data<f64>,
    node_ages: Data<u32>,
    section_info: SectionInfo,
}

impl Metadata {
    pub fn new(run_num: u32) -> Self {
        let dir = &format!("run{:02}", run_num);
        Metadata {
            step_num: 0,
            num_sections: Data::new(dir, "num_sections", "y"),
            num_nodes: Data::new(dir, "num_nodes", "y2"),
            num_malicious: Data::new(dir, "num_malicious", "y2"),
            most_malicious: Data::new(dir, "most_malicious", "y"),
            node_ages: Data::new(dir, "malicious_node_ages", ""),
            section_info: SectionInfo::new(dir),
        }
    }

    pub fn update(&mut self, net: &Network) {
        let groups = net.groups();
        self.num_sections.add_point(self.step_num, groups.len());
        self.num_nodes.add_point(self.step_num, count_nodes(groups));
        self.num_malicious.add_point(self.step_num, num_malicious_total(groups));
        self.update_most_malicious(groups);
        self.update_malicious_node_ages(groups);
        self.section_info.update(self.step_num, groups);
        self.step_num += 1;
    }

    fn update_most_malicious(&mut self, groups: &Groups) {
        let malicious = most_malicious_groups(groups);
        let frac = malicious.first().map(|&(_, frac)| frac).unwrap_or(0.0);
        self.most_malicious.add_point(self.step_num, frac);
    }

    fn update_malicious_node_ages(&mut self, groups: &Groups) {
        let node_ages = groups.values().flat_map(|group| {
            group.values()
                .filter(|node| node.is_malicious())
                .map(|node| node.age())
        });

        for age in node_ages {
            self.node_ages.add_point(self.step_num, age);
        }
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
    pub fn new(dir: &str, name: &str, yaxis: &str) -> Self {
        Data {
            dir: Path::new("viz").join(dir),
            name: name.to_string(),
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

    pub fn write_out(&self) -> io::Result<()> {
        let mut f = open_json_file(&self.dir, &self.name)?;
        write!(f, "{}", as_json(self))
    }
}

fn count_nodes(groups: &Groups) -> usize {
    groups.values().map(|group| group.len()).sum()
}

pub struct SectionInfo {
    path: PathBuf,
    sections: HashMap<Prefix, Data<usize>>,
    malicious: HashMap<Prefix, Data<usize>>
}

impl SectionInfo {
    pub fn new(dir: &str) -> Self {
        SectionInfo {
            path: Path::new("viz").join(dir),
            sections: HashMap::new(),
            malicious: HashMap::new()
        }
    }

    pub fn update(&mut self, step_num: usize, groups: &Groups) {
        for (prefix, group) in groups {
            let data_name = format!("{:?}", prefix).to_lowercase();
            let mut section_data = self.sections.entry(*prefix).or_insert_with(|| {
                Data::new("", &data_name, "y")
            });
            let mut malicious_data = self.malicious.entry(*prefix).or_insert_with(|| {
                Data::new("", &data_name, "y")
            });

            section_data.add_point(step_num, group.len());
            let num_mal = num_malicious(group);
            if num_mal > 0 {
                malicious_data.add_point(step_num, num_mal);
            }
        }
    }
}

impl Drop for SectionInfo {
    fn drop(&mut self) {
        let size_data = extract_data(&mut self.sections);
        let malicious_data = extract_data(&mut self.malicious);

        if let Err(e) = write_out_array(&self.path, "section_sizes", size_data).and(
                        write_out_array(&self.path, "section_mal", malicious_data)) {
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

fn open_json_file(dir: &Path, name: &str) -> io::Result<File> {
    create_dir_all(dir)?;
    File::create(dir.join(name.to_string() + ".json"))
}

fn write_out_array<T: Encodable>(dir: &Path, name: &str, data: Vec<Data<T>>) -> io::Result<()> {
    let f = open_json_file(dir, name)?;
    write!(&f, "{}", as_json(&data))
}

fn num_malicious_total(groups: &Groups) -> usize {
    groups.values().map(|g| num_malicious(g)).sum()
}

fn num_malicious(group: &Group) -> usize {
    group.values().filter(|n| n.is_malicious()).count()
}
