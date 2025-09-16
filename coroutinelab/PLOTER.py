import os
import re
import numpy as np
import matplotlib.pyplot as plt


def parse_file(filepath):
    """
    解析文件内容并提取数据
    """
    data = {}
    with open(filepath, 'r') as file:
        lines = file.readlines()

    for line in lines:
        if line.startswith("Size:"):
            data["size"] = int(line.split(":")[1].strip())
        elif line.startswith("Loops:"):
            data["loops"] = int(line.split(":")[1].strip())
        elif line.startswith("Batch size:"):
            data["batch_size"] = int(line.split(":")[1].strip())
        elif line.startswith("naive:"):
            match = re.search(r"([\d\.]+) ns per search", line)
            if match:
                data["naive_time"] = float(match.group(1))
        elif line.startswith("coroutine batched:"):
            match = re.search(r"([\d\.]+) ns per search", line)
            if match:
                data["coroutine_time"] = float(match.group(1))
    return data


def read_directory(directory):
    """
    读取目录下所有文件并解析数据
    """
    parsed_data = []
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            data = parse_file(filepath)
            if data:  # 如果数据有效
                parsed_data.append(data)
    return parsed_data


def create_heatmap(data, size):
    """
    为给定 size 绘制热力图 （横轴为 loops，纵轴为 batch，值为 coroutine/naive 的比值）
    """
    # 筛选出指定 size 的数据
    size_data = [entry for entry in data if entry["size"] == size]

    # 提取 loops 和 batch size 的所有唯一值
    loops = sorted(set(entry["loops"] for entry in size_data))
    batch_sizes = sorted(set(entry["batch_size"] for entry in size_data))

    # 创建二维数组存储比值 (coroutine_time / naive_time)
    ratio_matrix = np.zeros((len(batch_sizes), len(loops)))

    for entry in size_data:
        loop_idx = loops.index(entry["loops"])
        batch_idx = batch_sizes.index(entry["batch_size"])
        ratio_matrix[batch_idx,
                     loop_idx] = entry["coroutine_time"] / entry["naive_time"]

    # 绘制热力图
    plt.figure(figsize=(10, 8))
    heatmap = plt.imshow(ratio_matrix, cmap="coolwarm",
                         aspect="auto", origin="lower", vmin=0, vmax=2)
    plt.colorbar(
        heatmap, label="Coroutine/Naive Time Ratio (clipped to [0, 2])")
    plt.xticks(ticks=np.arange(len(loops)), labels=loops, rotation=45)
    plt.yticks(ticks=np.arange(len(batch_sizes)), labels=batch_sizes)
    plt.xlabel("Loops")
    plt.ylabel("Batch Size")
    plt.title(f"Heatmap for Size = {size} bytes")
    plt.show()


if __name__ == "__main__":
    # 设置目标目录
    directory = "./logs"  # 替换为实际目录路径

    # 读取目录并解析文件数据
    parsed_data = read_directory(directory)

    # 按 size 分组并绘制热力图
    sizes = sorted(set(entry["size"] for entry in parsed_data))
    for size in sizes:
        create_heatmap(parsed_data, size)
