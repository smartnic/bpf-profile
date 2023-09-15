import numpy as np
import matplotlib.pyplot as plt

def ccdf(packet_counts, output_file, elem_name):
    # Sort the flows by packet counts in descending order
    sorted_indices = np.argsort(packet_counts)[::-1]
    sorted_packet_counts = packet_counts[sorted_indices]
    total_flows = len(packet_counts)
    # Calculate the cumulative distribution of packet counts
    cumulative_counts = np.cumsum(sorted_packet_counts)
    # Calculate the function y = 1 - P(a randomly chosen packet is from the top x elems)
    x_values = np.arange(1, total_flows + 1)
    y_values = 1 - (cumulative_counts[x_values - 1] / np.sum(packet_counts))
    # Plot the function
    plt.figure(figsize=(8, 6))
    plt.plot(x_values, y_values, marker='o', linestyle='-')
    plt.xlabel(f'Top x {elem_name}')
    plt.ylabel(f'y = 1 - P(a randomly chosen packet is from the top x {elem_name})')
    plt.title(f'Packet distribution: {len(packet_counts)} {elem_name}, {np.sum(packet_counts)} packets')
    plt.grid(True)
    # plt.show()
    plt.savefig(output_file)

if __name__ == '__main__':
    total_flows = 10000
    np.random.seed(0)
    packet_counts = np.random.randint(1, 100, total_flows)
    ccdf(packet_counts)
