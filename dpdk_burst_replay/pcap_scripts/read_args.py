import yaml

class WorkItem():
    def __init__(self):
        self.input_file = None
        self.output = None
        self.max_flows = 0
        self.pkt_len = 0
        self.tcp_only = False
        self.num_cores = None
        self.dst_mac = None
        self.tasks = {}
        self.input_file_conntrack = None

    def __str__(self):
        res = f"input_file: {self.input_file}\n"
        res += f"output: {self.output}\n"
        res += f"max_flows: {self.max_flows}\n"
        res += f"pkt_len: {self.pkt_len}\n"
        res += f"tcp_only: {self.tcp_only}\n"
        res += f"num_cores: {self.num_cores}\n"
        res += f"dst_mac: {self.dst_mac}\n"
        res += f"tasks: {self.tasks}\n"
        res += f"input_file_conntrack: {self.input_file_conntrack}\n"
        return res

    def __copy__(self):
        x = WorkItem()
        x.input_file = self.input_file
        x.output = self.output
        x.max_flows = self.max_flows
        x.pkt_len = self.pkt_len
        x.tcp_only = self.tcp_only
        x.num_cores = self.num_cores
        x.dst_mac = self.dst_mac
        x.tasks = self.tasks
        x.input_file_conntrack = self.input_file_conntrack
        return x


def read_args_from_yaml(yaml_file):
    # Read the YAML file
    with open(yaml_file, "r") as file:
        data = yaml.safe_load(file)

    item_list = []
    # Process the data
    for x in data.get("items", []):
        pkt_len_list = []
        if x.get("pkt_len"):
            pkt_len_list = str(x.get("pkt_len")).split(",")
            pkt_len_list = [int(l.strip()) for l in pkt_len_list]
        item = WorkItem()
        item.input_file = x.get("input")
        item.output = x.get("output")
        item.max_flows = int(x.get("max_flows"))
        item.tcp_only = x.get("tcp_only")
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
        for l in pkt_len_list:
            new_item = item.__copy__()
            new_item.output += f"/{l}/"
            new_item.pkt_len = l
            item_list.append(new_item)
    print("Work item list:")
    for x in item_list:
        print(x)
    return item_list

if __name__ == "__main__":
    # Path to your YAML file
    yaml_file = "gen_pcap_config.yaml"

    read_args_from_yaml(yaml_file)