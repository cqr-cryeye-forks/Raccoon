import argparse


def init_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--storage", required=True)
    parser.add_argument("--target", required=True)

    parser.add_argument("--vulners-nmap-scan", required=False, action='store_true')
    parser.add_argument("--follow-redirects", required=False,  action='store_true')

    parser.add_argument("--cookies", required=False)
    parser.add_argument("--proxy", required=False)
    parser.add_argument("--threads", required=False)
    parser.add_argument("--tls-port", required=False)

    return parser.parse_args()


args: argparse.Namespace = init_args()
