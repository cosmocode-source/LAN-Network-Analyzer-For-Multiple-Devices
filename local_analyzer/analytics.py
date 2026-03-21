def device_summary(df):
    summary = df.groupby("device_name").agg(
        avg_latency=("latency_ms", "mean"),
        avg_throughput=("throughput_Mbps", "mean"),
        avg_handshake=("tcp_handshake_ms", "mean"),
        stability=("connection_duration_sec", "std"),
        transfer_variance=("throughput_Mbps", "var"),
        tests=("device_name", "count")
    )

    summary = summary.fillna(0)
    return summary


def compute_best_device(summary):
    best_latency = summary["avg_latency"].idxmin()
    best_throughput = summary["avg_throughput"].idxmax()
    most_stable = summary["stability"].idxmin()

    return {
        "best_latency": best_latency,
        "best_throughput": best_throughput,
        "most_stable": most_stable
    }


def compute_percentage_difference(summary):
    fastest = summary["avg_throughput"].max()
    summary["throughput_percent"] = (summary["avg_throughput"] / fastest) * 100
    return summary.round(2)