"""
file: subnet-calculator.py
Usage: subnet-calculator.py
description: This program will calculate possible subnets
                and their details based user inputs
language: python3
author: Abhishek Inamdar (ai2363@rit.edu)
"""
import sys


class IP(object):
    __slots__ = 'ipDec', 'ipBin', 'completeBin', 'ipStr'

    def __init__(self, ip_str):
        self.ipDec = [0] * 4
        self.ipBin = [0] * 4
        self.completeBin = ''
        if "." in ip_str:
            array = ip_str.split(".")
            i = 0
            for element in array:
                self.ipDec[i] = int(element)
                self.ipBin[i] = "{0:008b}".format(int(self.ipDec[i]))
                self.completeBin += self.ipBin[i]
                i += 1

        self.ipStr = ""
        for i in range(4):
            self.ipStr += str(self.ipDec[i]) + "."
        self.ipStr = self.ipStr[:-1]

    def __str__(self):
        string = self.ipStr
        string += "\tBinary: "
        string += self.completeBin
        return string


def perform_bit_and(ip, mask):
    result = ""
    for i in range(len(ip)):
        result += str(int(ip[i], 2) & int(mask[i], 2))
    return result


def get_network_bits(mask):
    count = 0
    for i in mask:
        if int(i) == 1:
            count += 1
    return count


def get_ip_address_from_binary_string(string):
    ipStr = ""
    for octet in (string[i:i + 8] for i in range(0, len(string), 8)):
        ipStr += str(int(octet, 2)) + "."
    ipStr = ipStr[:-1]
    return IP(ipStr)


def get_broadcast_addr_binary(network_id, mask):
    addrBin = ""
    for i in range(32):
        if int(mask.completeBin[i]) == 1:
            addrBin += network_id.completeBin[i]
        else:
            addrBin += str(1)
    return addrBin


class Subnet(object):
    __slots__ = 'network_id', 'subnet_mask', 'broadcast_address', \
                'routerLowAddr', 'routerHighAddr', \
                'network_bits', 'host_bits', \
                'possible_hosts', 'usable_hosts'

    def __init__(self, network_id, subnet_mask):
        self.network_id = network_id
        self.subnet_mask = subnet_mask
        self.network_bits = get_network_bits(subnet_mask.completeBin)
        self.host_bits = 32 - self.network_bits

        self.possible_hosts = pow(2, self.host_bits)
        self.usable_hosts = self.possible_hosts - 2

        broadcastBin = get_broadcast_addr_binary(network_id, subnet_mask)
        self.broadcast_address = get_ip_address_from_binary_string(broadcastBin)

        networkBin = self.network_id.completeBin

        self.routerLowAddr = get_ip_address_from_binary_string(networkBin[:31] + "1")
        self.routerHighAddr = get_ip_address_from_binary_string(broadcastBin[:31] + "0")

    def __str__(self):
        string = ""
        # string += "\nPossible hosts: " + str(self.possible_hosts)
        # string += "\nUsable hosts: " + str(self.usable_hosts)
        string += "Subnet Range: "
        string += "\n\tStarting Address: " + str(self.network_id)
        string += "\n\tEnding Address: " + str(self.broadcast_address)
        string += "\nNetwork Id: " + str(self.network_id)
        string += "\nBroadcast Id: " + str(self.broadcast_address)

        string += "\nRange of usable addresses: "
        string += "\n\tFrom: " + str(self.routerLowAddr)
        string += "\n\tTo: " + str(self.routerHighAddr)

        string += "\nPossible Router Addresses: "
        string += "\n\tLow: " + str(self.routerLowAddr)
        string += "\n\tHigh: " + str(self.routerHighAddr)
        string += "\n"
        return string


class Network(object):
    __slots__ = 'ip_str', 'ip', 'ip_class', 'mask', \
                'network_id', 'subnet'

    def __init__(self, ip_str):
        self.ip_str = ip_str
        self.ip = IP(ip_str)
        if 0 <= self.ip.ipDec[0] <= 127:
            self.ip_class = 'A'
            self.mask = IP("255.0.0.0")
        elif 128 <= self.ip.ipDec[0] <= 191:
            self.ip_class = 'B'
            self.mask = IP("255.255.0.0")
        else:
            # Assumption final value allowed will be 223
            self.ip_class = 'C'
            self.mask = IP("255.255.255.0")

        self.network_id = get_ip_address_from_binary_string(
            perform_bit_and(self.ip.completeBin, self.mask.completeBin))
        self.subnet = Subnet(self.network_id, self.mask)

    def __str__(self):
        string = 'IP: ' + str(self.ip_str)
        string += '\nSubnet Mask: ' + self.mask.ipStr
        string += '\nNetwork Address: ' + self.network_id.ipStr

        string += '\nRange of Addresses'
        string += '\n\tStart: ' + self.subnet.network_id.ipStr
        string += '\n\tEnd: ' + self.subnet.broadcast_address.ipStr
        string += '\nPossible Router Addresses'
        string += '\n\tLow: ' + self.subnet.routerLowAddr.ipStr
        string += '\n\tHigh: ' + self.subnet.routerHighAddr.ipStr
        return string


def validate_ip(string):
    """
    validates given string for IPv4 IP address format
    :param string: string to be validated
    :return: 'valid' if string is valid IPv4 format, else invalid reason
    """
    if "." in string:
        array = string.split(".")
        if len(array) == 4:
            for element in array:
                if element.isnumeric() and 0 <= int(element) <= 255:
                    return 'valid'
                return 'Not a valid value'
        else:
            return 'Not a valid length'
    return 'Not a valid format'


def get_ip_from_user():
    """
    Prompts user to enter IP address, and validates it
    :return: User entered IP address after validation
    """
    ip = input("Please enter an IP address : ")

    # validation
    is_ip_valid = validate_ip(ip)

    # loop to re-prompt and re-validate
    while is_ip_valid != 'valid':
        print("Invalid Entry: " + is_ip_valid)
        ip = input("Please enter an IP address ('exit' to end the program): ")
        if ip == 'exit':
            sys.exit("Exiting!")
        is_ip_valid = validate_ip(ip)
    return ip


def not_supported(ip):
    """
    Checks for non supporting ip addresses
    :pre: validate_ip(ip)
    :param ip: ip string to be checked for support
    :return: True if supported, False otherwise
    """
    array = ip.split(".")
    return (0 <= int(array[0]) <= 223) is False


def validate_subnet_input(subnetCount, host_bits):
    if subnetCount.isnumeric() and int(subnetCount) > 0:
        bits_required = int(subnetCount).bit_length()
        if bits_required < host_bits - 1:
            return 'valid'
        elif bits_required >= host_bits:
            return 'Number of subnets is too high'
        else:
            return 'No usable hosts in each subnets'
    else:
        return 'Should be Positive Numeric value'


def get_subnet_count(host_bits):
    """
    Prompts user and returns number of subnets required
    :param host_bits:
    :return:
    """
    subnetCount = input("Please enter number of subnets to be created : ")

    is_valid_subnet = validate_subnet_input(subnetCount, host_bits)

    # loop to re-prompt and re-validate
    while is_valid_subnet != 'valid':
        print("Invalid Entry: " + is_valid_subnet)
        subnetCount = input("Please enter number of subnets to be created ('exit' to end the program): ")
        if subnetCount == 'exit':
            sys.exit("Exiting!")
        is_valid_subnet = validate_subnet_input(subnetCount, host_bits)
    return subnetCount


def get_stolen_bits(num, bits_required):
    """
    Returns binary representation of given number in given length
    :param num: Number to be converted
    :param bits_required: Length of Number of bits required
    :return: Binary string of given number
    """
    binary = "{0:b}".format(int(num))
    prefix = bits_required - len(binary)
    prefix_str = ""
    if prefix > 0:
        prefix_str = "0" * prefix
    return prefix_str + binary


def get_subnet_network_id_bin(orig_network_bin, num, orig_network_bits, bits_required, new_host_bits):
    """
    Calculates and returns binary representation of subnet network Id
    :param orig_network_bin: Original Network Id
    :param num: Number in Decimal to be used for stolen bits
    :param orig_network_bits: number of original network bits
    :param bits_required: number of stolen bits
    :param new_host_bits: number of new host bits
    :return: Binary representation of 32 bit Network Id
    """
    result_str = ""
    for i in range(orig_network_bits):
        result_str += orig_network_bin[i]

    result_str += get_stolen_bits(num, bits_required)

    result_str += "0" * new_host_bits

    return result_str


def createSubnets(subnetCount, network, showSubnetCount):
    """
    Creates Subnets
    :param subnetCount: Number of Subnets to be created total
    :param network: Network object
    :param showSubnetCount: First N number of subnets to be created
    :return: Created Subnets
    """
    bits_required = int(subnetCount).bit_length() - 1
    orig_network_bin = network.network_id.completeBin
    orig_network_bits = network.subnet.network_bits
    new_network_bits = orig_network_bits + bits_required
    new_host_bits = 32 - new_network_bits

    new_mask_bin = ""
    for i in range(new_network_bits):
        new_mask_bin += "1"
    for i in range(new_host_bits):
        new_mask_bin += "0"

    new_mask = get_ip_address_from_binary_string(new_mask_bin)
    subnets = []
    if subnetCount <= showSubnetCount:
        # creating all subnets
        for i in range(subnetCount):
            network_id_bin = get_subnet_network_id_bin(orig_network_bin,
                                                       i, orig_network_bits,
                                                       bits_required, new_host_bits)
            network_id = get_ip_address_from_binary_string(network_id_bin)

            subnets.append(Subnet(network_id, new_mask))
    else:
        # create first showSubnetCount subnets
        for i in range(showSubnetCount):
            network_id_bin = get_subnet_network_id_bin(orig_network_bin,
                                                       i, orig_network_bits,
                                                       bits_required, new_host_bits)
            network_id = get_ip_address_from_binary_string(network_id_bin)
            subnets.append(Subnet(network_id, new_mask))

        # Last Subnet
        network_id_bin = get_subnet_network_id_bin(orig_network_bin, pow(2, bits_required) - 1,
                                                   orig_network_bits, bits_required,
                                                   new_host_bits)
        network_id = get_ip_address_from_binary_string(network_id_bin)
        subnets.append(Subnet(network_id, new_mask))
    return subnets


def print_subnet_results(bits_stolen, subnetCount, subnets):
    """
    Prints results for subnets
    :param bits_stolen: Number of bits stolen
    :param subnetCount: Subnet Count
    :param subnets: Created Subnets
    :return: None
    """
    print("Number of bits needed to be stolen: " + str(bits_stolen))
    print("New Subnet Mask: " + str(subnets.__getitem__(0).subnet_mask))
    print("Number of subnets created: " + str(subnetCount))
    print("Total Number of hosts per subnet: " + str(subnets.__getitem__(0).possible_hosts))

    subnetsSize = len(subnets)

    for i in range(len(subnets)):
        if i + 1 == subnetsSize:
            print("Last Subnet:")
        else:
            print("Subnet " + str(i + 1) + ":")
        print(subnets.__getitem__(i))


def main():
    """
    Main method
    :return: None
    """
    # User input
    ip = get_ip_from_user()
    if not_supported(ip):
        print("Currently program does not support given IP address.")
        sys.exit("Exiting!")

    # Original network
    network = Network(ip)
    print(network)

    # get user input about subnet count
    subnetCount = get_subnet_count(network.subnet.host_bits)
    bits_stolen = int(subnetCount).bit_length()
    subnetCount = pow(2, bits_stolen)

    # create subnets
    subnets = createSubnets(subnetCount, network, 5)

    # print results
    print_subnet_results(bits_stolen, subnetCount, subnets)


if __name__ == '__main__':
    main()
