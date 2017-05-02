use node::Prefix;
use net::{Group, Groups, Network};
use std::io::{self, Write};
use std::fs::{File, create_dir_all};
use std::path::{Path, PathBuf};
use rustc_serialize::json::as_json;
use std::collections::HashMap;
use attack::{MaliciousMetric, most_malicious_groups};
use rustc_serialize::{Encodable};

#[derive(RustcEncodable, Clone)]
pub struct Data<T: Encodable> {
    pub dir: PathBuf,
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
    most_malicious_count: Data<f64>,
    most_malicious_age: Data<f64>,
    node_ages: Data<u32>,
    section_info: SectionInfo,
    corrupt_data: Data<f64>,
    double_vote: Data<f64>,
    enabled: bool,
}

impl Metadata {
    pub fn new(dir: &str, write_out: bool) -> Self {
        Metadata {
            step_num: 0,
            num_sections: Data::new(dir, "num_sections", "y", write_out),
            num_nodes: Data::new(dir, "num_nodes", "y2", write_out),
            num_malicious: Data::new(dir, "num_malicious", "y2", write_out),
            most_malicious_count: Data::new(dir, "most_malicious_count", "y", write_out),
            most_malicious_age: Data::new(dir, "most_malicious_age", "y", write_out),
            node_ages: Data::new(dir, "malicious_node_ages", "", write_out),
            section_info: SectionInfo::new(dir, write_out),
            corrupt_data: Data::new(dir, "corrupt_data", "", write_out),
            double_vote: Data::new(dir, "double_vote", "", write_out),
            enabled: write_out,
        }
    }

    pub fn update(&mut self, net: &Network, double_vote_prob: f64, corrupt_fraction: f64) {
        if !self.enabled {
            return;
        }
        let groups = net.groups();
        self.num_sections.add_point(self.step_num, groups.len());
        self.num_nodes.add_point(self.step_num, count_nodes(groups));
        self.num_malicious.add_point(self.step_num, num_malicious_total(groups));
        self.update_most_malicious(groups);
        self.update_malicious_node_ages(groups);
        self.section_info.update(self.step_num, groups);
        self.corrupt_data.add_point(self.step_num, corrupt_fraction);
        self.double_vote.add_point(self.step_num, double_vote_prob);
        self.step_num += 1;
    }

    fn update_most_malicious(&mut self, groups: &Groups) {
        let malicious = most_malicious_groups(groups, MaliciousMetric::NodeFraction);
        let (age_frac, node_frac) = malicious.first().map(|&(prefix, node_frac)| {
            let age_frac = MaliciousMetric::AgeFraction.calculate(&groups[&prefix]);
            (age_frac, node_frac)
        }).unwrap_or((0.0, 0.0));
        self.most_malicious_count.add_point(self.step_num, node_frac);
        self.most_malicious_age.add_point(self.step_num, age_frac);
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
    pub fn new(dir: &str, name: &str, yaxis: &str, write_out: bool) -> Self {
        Data {
            dir: Path::new("viz").join(dir),
            name: name.to_string(),
            x: vec![],
            y: vec![],
            yaxis: yaxis.into(),
            write_out: write_out,
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
    malicious: HashMap<Prefix, Data<usize>>,
    write_out: bool,
}

impl SectionInfo {
    pub fn new(dir: &str, write_out: bool) -> Self {
        SectionInfo {
            path: Path::new("viz").join(dir),
            sections: HashMap::new(),
            malicious: HashMap::new(),
            write_out: write_out,
        }
    }

    pub fn update(&mut self, step_num: usize, groups: &Groups) {
        for (prefix, group) in groups {
            let data_name = format!("{:?}", prefix).to_lowercase();
            let mut section_data = self.sections.entry(*prefix).or_insert_with(|| {
                Data::new("", &data_name, "y", false)
            });
            let mut malicious_data = self.malicious.entry(*prefix).or_insert_with(|| {
                Data::new("", &data_name, "y", false)
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
        if !self.write_out {
            return;
        }

        let size_data = extract_data(&mut self.sections);
        let malicious_data = extract_data(&mut self.malicious);

        if let Err(e) = write_out_array(&self.path, "section_sizes", size_data).and(
                        write_out_array(&self.path, "section_mal", malicious_data)) {
            error!("Failed to write SectionInfo metadata: {:?}", e);
        }
    }
}

fn extract_data<T: Encodable>(data_map: &mut HashMap<Prefix, Data<T>>) -> Vec<Data<T>> {
    data_map.drain().map(|(_, data)| data).collect()
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
