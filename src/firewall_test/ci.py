from os import path as os_path
from sys import path as sys_path

# pylint: disable=C0413
sys_path.append(os_path.dirname(os_path.abspath(__file__)))


def main():
    print('ENTERING Firewall-Testing-Framework in automated Mode')
    print('EXIT: This project is still in the conception-phase')


if __name__ == '__main__':
    main()
