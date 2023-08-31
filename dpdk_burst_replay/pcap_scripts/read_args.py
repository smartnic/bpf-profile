import yaml

class WorkItem():
    def __init__(self):
        self.input_file = None
        self.output = None
        self.max_pkt_len = 0
        self.num_cores = None
        self.dst_mac = None
        self.tasks = {}

    def __str__(self):
        res = f"input_file: {self.input_file}\n"
        res += f"output: {self.output}\n"
        res += f"max_pkt_len: {self.max_pkt_len}\n"
        res += f"num_cores: {self.num_cores}\n"
        res += f"dst_mac: {self.dst_mac}\n"
        res += f"tasks: {self.tasks}\n"
        return res

    def __copy__(self):
        x = WorkItem()
        x.input_file = self.input_file
        x.output = self.output
        x.max_pkt_len = self.max_pkt_len
        x.num_cores = self.num_cores
        x.dst_mac = self.dst_mac
        x.tasks = self.tasks
        return x


def read_args_from_yaml(yaml_file):
    # Read the YAML file
    with open(yaml_file, "r") as file:
        data = yaml.safe_load(file)

    item_list = []
    # Process the data
    for x in data.get("items", []):
        max_pkt_len_list = []
        if x.get("max_pkt_len"):
            max_pkt_len_list = x.get("max_pkt_len").split(",")
            max_pkt_len_list = [int(l.strip()) for l in max_pkt_len_list]
        item = WorkItem()
        item.input_file = x.get("input")
        item.output = x.get("output")
        item.num_cores = int(x.get("num_cores"))
        item.dst_mac = x.get("dst_mac")
        task_list = x.get("tasks", [])
        for task in task_list:
            benchmark, approaches = list(task.items())[0]
            approaches = approaches.split(",")
            approaches = [string.strip() for string in approaches]
            for a in approaches:
                if a in item.tasks:
                    item.tasks[a].append(benchmark)
                else:
                    item.tasks[a] = [benchmark]
        for l in max_pkt_len_list:
            new_item = item.__copy__()
            new_item.output += f"/max_{l}/"
            new_item.max_pkt_len = l
            item_list.append(new_item)
    print("Work item list:")
    for x in item_list:
        print(x)
    return item_list

if __name__ == "__main__":
    # Path to your YAML file
    yaml_file = "gen_pcap_config.yaml"

    read_args_from_yaml(yaml_file)