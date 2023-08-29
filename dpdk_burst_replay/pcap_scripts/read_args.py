import yaml

class WorkItem():
    def __init__(self):
        self.input_file = None
        self.output = None
        self.num_cores = None
        self.dst_mac = None
        self.tasks = {}

    def __str__(self):
        res = f"input_file: {self.input_file}\n"
        res += f"output: {self.output}\n"
        res += f"num_cores: {self.num_cores}\n"
        res += f"dst_mac: {self.dst_mac}\n"
        res += f"tasks: {self.tasks}\n"
        return res


def read_args_from_yaml(yaml_file):
    # Read the YAML file
    with open(yaml_file, "r") as file:
        data = yaml.safe_load(file)

    item_list = []
    # Process the data
    for x in data.get("items", []):
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
        item_list.append(item)
    print("Work item list:")
    for x in item_list:
        print(x)
    return item_list

if __name__ == "__main__":
    # Path to your YAML file
    yaml_file = "gen_pcap_config.yaml"

    read_args_from_yaml(yaml_file)