def interpret_latency(value):

    if value < 50:
        return "Extremely low latency indicating close geographic proximity and efficient routing."

    if value < 120:
        return "Good latency for international connections."

    if value < 200:
        return "Moderate latency likely due to longer routing paths."

    return "High latency suggesting distant servers or congested routes."


def interpret_handshake(value):

    if value < 80:
        return "Fast TCP connection establishment."

    if value < 150:
        return "Normal TCP handshake duration."

    return "Slow TCP connection setup which may indicate network delay."


def interpret_throughput(value):

    if value > 150:
        return "High bandwidth availability."

    if value > 80:
        return "Stable network throughput."

    if value > 40:
        return "Moderate throughput."

    return "Low throughput indicating congestion or limited bandwidth."


def interpret_variance(value):

    if value < 0.005:
        return "Very stable data transfer."

    if value < 0.02:
        return "Moderate jitter detected."

    return "High variance indicating unstable connection."