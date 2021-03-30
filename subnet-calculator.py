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
    """
    IP object
    """
    __slots__ = 'ip_decimal', 'ip_binary', 'ip_binary_string', 'ip_string'

    def __init__(self, ip_str):
        self.ip_decimal = [0] * 4
        self.ip_binary = [0] * 4
        self.ip_binary_string = ''
        if "." in ip_str:
            array = ip_str.split(".")
            i = 0
            for element in array:
                self.ip_decimal[i] = int(element)
                self.ip_binary[i] = "{0:008b}".format(int(self.ip_decimal[i]))
                self.ip_binary_string += self.ip_binary[i]
                i += 1

        self.ip_string = ""
        for i in range(4):
            self.ip_string += str(self.ip_decimal[i]) + "."
        self.ip_string = self.ip_string[:-1]

    def __str__(self):
        string = self.ip_string
        string += "\tBinary: "
        string += self.ip_binary_string
        return string


def perform_bitwise_and(ip, mask):
    """
    Performs bitwise AND operation on given two binary strings
    :pre: length of two binary strings should be identical
    :param ip: First binary string
    :param mask: First binary string
    :return: Binary string after Bitwise AND operation
    """
    result = ""
    for i in range(len(ip)):
        result += str(int(ip[i], 2) & int(mask[i], 2))
    return result


def get_network_bits(mask_binary):
    """
    Returns number of network bits of given mask
    :param mask_binary: Subnet Mask in binary
    :return: Number of network bits
    """
    count = 0
    for i in mask_binary:
        if int(i) == 1:
            count += 1
    return count


def get_ip_address_from_binary_string(string):
    """
    returns IP object from given binary string
    :param string: binary string of IP address
    :return: IP object
    """
    ipStr = ""
    for octet in (string[i:i + 8] for i in range(0, len(string), 8)):
        ipStr += str(int(octet, 2)) + "."
    ipStr = ipStr[:-1]
    return IP(ipStr)


def get_broadcast_address_binary(network_id, mask):
    """
    Gets binary representation of broadcast IP address
    based on given network Id and Mask
    :param network_id: Network Id
    :param mask: Mask
    :return: Broadcast address in Binary
    """
    address_bin = ""
    for i in range(32):
        if int(mask.ip_binary_string[i]) == 1:
            address_bin += network_id.ip_binary_string[i]
        else:
            address_bin += str(1)
    return address_bin


class Subnet(object):
    """
    Subnet Object
    """
    __slots__ = 'network_id', 'subnet_mask', 'broadcast_address', \
                'router_low_address', 'router_high_address', \
                'network_bits', 'host_bits', \
                'possible_hosts', 'usable_hosts'

    def __init__(self, network_id, subnet_mask):
        self.network_id = network_id
        self.subnet_mask = subnet_mask
        self.network_bits = get_network_bits(subnet_mask.ip_binary_string)
        self.host_bits = 32 - self.network_bits

        self.possible_hosts = pow(2, self.host_bits)
        self.usable_hosts = self.possible_hosts - 2

        broadcastBin = get_broadcast_address_binary(network_id, subnet_mask)
        self.broadcast_address = get_ip_address_from_binary_string(broadcastBin)

        networkBin = self.network_id.ip_binary_string

        self.router_low_address = get_ip_address_from_binary_string(networkBin[:31] + "1")
        self.router_high_address = get_ip_address_from_binary_string(broadcastBin[:31] + "0")

    def __str__(self):
        string = str(self.network_id.ip_string)
        string += " - " + str(self.broadcast_address.ip_string)
        string += "\t\t" + str(self.network_id.ip_string)
        string += "\t\t" + str(self.broadcast_address.ip_string)

        string += "\t\t" + str(self.router_low_address.ip_string)
        string += " - " + str(self.router_high_address.ip_string)

        string += "\t\t" + str(self.router_low_address.ip_string)
        string += ", " + str(self.router_high_address.ip_string)
        return string


class Network(object):
    """
    Network Object
    """
    __slots__ = 'ip_str', 'ip', 'ip_class', 'mask', \
                'network_id', 'subnet'

    def __init__(self, ip_str):
        self.ip_str = ip_str
        self.ip = IP(ip_str)
        if 0 <= self.ip.ip_decimal[0] <= 127:
            self.ip_class = 'A'
            self.mask = IP("255.0.0.0")
        elif 128 <= self.ip.ip_decimal[0] <= 191:
            self.ip_class = 'B'
            self.mask = IP("255.255.0.0")
        else:
            # Assumption final value allowed will be 223
            self.ip_class = 'C'
            self.mask = IP("255.255.255.0")

        self.network_id = get_ip_address_from_binary_string(
            perform_bitwise_and(self.ip.ip_binary_string, self.mask.ip_binary_string))
        self.subnet = Subnet(self.network_id, self.mask)

    def __str__(self):
        string = 'Network of ' + str(self.ip_str)
        string += '\nNetwork Mask\tNetwork Id\t\tDirected Broadcast' \
                  '\t\tRange of Addresses\t\t\t\tPossible Router Addresses'
        string += '\n' + self.mask.ip_string \
                  + '\t' + self.network_id.ip_string \
                  + '\t' + self.subnet.broadcast_address.ip_string \
                  + '\t\t\t' + self.subnet.network_id.ip_string \
                  + ' - ' + self.subnet.broadcast_address.ip_string \
                  + '\t' + self.subnet.router_low_address.ip_string \
                  + ', ' + self.subnet.router_high_address.ip_string
        return string


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


def create_subnets(subnetCount, network, showSubnetCount):
    """
    Creates Subnets
    :param subnetCount: Number of Subnets to be created total
    :param network: Network object
    :param showSubnetCount: First N number of subnets to be created
    :return: Created Subnets
    """
    bits_required = int(subnetCount - 1).bit_length()
    orig_network_bin = network.network_id.ip_binary_string
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


def validate_ip(string):
    """
    validates given string for IPv4 IP address format
    :param string: string to be validated
    :return: 'valid' if string is valid IPv4 format, else invalid reason
    """
    result = 'IP address contains invalid value'
    if "." in string:
        array = string.split(".")
        if len(array) == 4:
            for element in array:
                if element.isnumeric() and 0 <= int(element) <= 255:
                    result = 'valid'
                else:
                    result = 'IP address contains invalid value'
                    break
        else:
            result = 'IP address contains invalid length'
    else:
        result = 'IP address contains invalid format'

    if result == 'valid':
        if not_supported(string):
            result = 'IP address not supported'
        else:
            result = 'valid'

    return result


def not_supported(ip):
    """
    Checks for non supporting ip addresses
    :pre: validate_ip(ip)
    :param ip: ip string to be checked for support
    :return: True if Not supported, False otherwise
    """
    array = ip.split(".")
    return int(array[0]) <= 0 or int(array[0]) == 127 or int(array[0]) > 223


def validate_subnet_input(subnetCount, host_bits):
    """
    Validates Subnet count input
    :param subnetCount: Subnet count from user input
    :param host_bits: Number of host bits of from the network object
    :return: 'valid' if subnetCount is valid, Invalid reason otherwise
    """
    if subnetCount.isnumeric() and int(subnetCount) > 0:
        bits_required = (int(subnetCount) - 1).bit_length()
        if bits_required < host_bits - 1:
            return 'valid'
        elif bits_required >= host_bits:
            return "'Subnets to be created value' is too high"
        else:
            return "There will not be any usable host in each subnet with given 'Subnets to be created value'"
    else:
        return 'Subnets to be created value should be Positive Numeric value'


def get_ip_subnet_from_user():
    """
    Prompts user for input and returns it
    :return: User input of IP address and Subnet Count
    """
    ip = input("Please enter an 'IP address' : ")
    if ip == 'exit':
        return ip, 0
    subnetCount = input("Please enter number of 'Subnets to be created' : ")
    return ip, subnetCount


def get_user_input():
    """
    Prompts user for input, validates it
    and returns network object and subnet count
    :return: Network object and subnet count
    """
    (ip, subnetCount) = get_ip_subnet_from_user()

    is_ip_valid = validate_ip(ip)
    # loop to re-prompt and re-validate
    while is_ip_valid != 'valid':
        print("Invalid Entry: " + is_ip_valid)
        print("Please try again! (Enter 'exit' to end the program)")
        (ip, subnetCount) = get_ip_subnet_from_user()
        if ip == 'exit':
            sys.exit("Exiting!!")
        is_ip_valid = validate_ip(ip)

    # Create Network object
    network = Network(ip)

    is_valid_subnet = validate_subnet_input(subnetCount, network.subnet.host_bits)
    # loop to re-prompt and re-validate
    while is_valid_subnet != 'valid':
        print("Invalid Entry: " + is_valid_subnet)
        print("Please try again! (Enter 'exit' to end the program)")
        (ip, subnetCount) = get_ip_subnet_from_user()
        if ip == 'exit':
            sys.exit("Exiting!!")
        is_valid_subnet = validate_subnet_input(subnetCount, network.subnet.host_bits)

    # return network object and subnet count
    return network, subnetCount


def print_subnet_results(network, bits_stolen, subnetCount, calSubnetCount, subnets):
    """
    Prints results for subnets
    :param network: Network Object
    :param bits_stolen: Number of bits stolen
    :param subnetCount: Original Subnet count
    :param calSubnetCount: Subnet Count
    :param subnets: Created Subnets
    :return: None
    """
    # Print Original network
    print("{:<18} {:<18} {:<18} {:<38} {:<38}".format('Network Mask', 'Network Id',
                                                      'Directed Broadcast', 'Range of addresses',
                                                      'Possible Router Addresses'))
    print("{:<18} {:<18} {:<18} {:<38} {:<38}"
        .format(
        network.mask.ip_string,

        network.subnet.network_id.ip_string,

        network.subnet.broadcast_address.ip_string,

        network.subnet.network_id.ip_string + " - "
        + network.subnet.broadcast_address.ip_string,

        network.subnet.router_low_address.ip_string + ", "
        + network.subnet.router_high_address.ip_string,
    ))

    print("\nFor " + str(subnetCount) + " subnets, " + str(bits_stolen)
          + " bits will be stolen to create total of " + str(calSubnetCount) + " subnets")
    print("New Subnet Mask will be " + str(subnets.__getitem__(0).subnet_mask.ip_string)
          + " (Binary:" + subnets.__getitem__(0).subnet_mask.ip_binary_string + ")")
    print("There will be " + str(subnets.__getitem__(0).usable_hosts) + " useable hosts per subnet")
    print("\nCreated Subnets:")

    print("{:<10} {:<38} {:<18} {:<18} {:<38} {:<38}".format('Subnet #', 'Network Range', 'Network Id',
                                                             'Directed Broadcast', 'Range of Useable addresses',
                                                             'Possible Router Addresses'))
    subnetsSize = len(subnets)
    for i in range(len(subnets)):
        k = str(i + 1)
        if i + 1 == subnetsSize:
            k = str(calSubnetCount)

        print("{:<10} {:<38} {:<18} {:<18} {:<38} {:<38}"
            .format(
            k,

            subnets.__getitem__(i).network_id.ip_string + " - "
            + subnets.__getitem__(i).broadcast_address.ip_string,

            subnets.__getitem__(i).network_id.ip_string,

            subnets.__getitem__(i).broadcast_address.ip_string,

            subnets.__getitem__(i).router_low_address.ip_string + " - "
            + subnets.__getitem__(i).router_high_address.ip_string,

            subnets.__getitem__(i).router_low_address.ip_string + ", "
            + subnets.__getitem__(i).router_high_address.ip_string
        ))

        print("{:<10} {:<38} {:<18} {:<18} {:<38} {:<38}"
            .format(
            "Binary",
            subnets.__getitem__(i).network_id.ip_binary_string + " - ",
            "",
            "",
            subnets.__getitem__(i).router_low_address.ip_binary_string + " - ",
            ""
        ))

        print("{:<10} {:<38} {:<18} {:<18} {:<38} {:<38}"
            .format(
            "Addresses",
            subnets.__getitem__(i).broadcast_address.ip_binary_string,
            "",
            "",
            subnets.__getitem__(i).router_high_address.ip_binary_string,
            ""
        ))
        print("\n")


def main():
    """
    Main method
    :return: None
    """
    # User input
    (network, subnetCount) = get_user_input()

    bits_stolen = (int(subnetCount) - 1).bit_length()
    if bits_stolen <= 0:
        print("No need to Subnet")
        sys.exit("Exiting!")

    calSubnetCount = pow(2, bits_stolen)

    # create subnets
    subnets = create_subnets(calSubnetCount, network, 5)

    # Print results
    print_subnet_results(network, bits_stolen, subnetCount, calSubnetCount, subnets)


if __name__ == '__main__':
    main()
