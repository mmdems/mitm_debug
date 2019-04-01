import scapy.all as sc
import time


def receiving(pattern, mac, received_packets):
    """"""
    packets_total_from_device = 0
    other_packets, error_cnt = 0, 0
    packets_total_with_pattern = 0
    byte_packets = [bytes(packet) for packet in received_packets]
    for packet in byte_packets:
        if packet[6:12] == mac:
            packets_total_from_device += 1
            if packet[-4:] == pattern:
                packets_total_with_pattern += 1
                if packets_total_with_pattern == 1:
                    current_id = packet[-5]
                else:
                    if current_id == 255:
                        if packet[-5] != 0:
                            error_cnt += 1
                    else:
                        if packet[-5] != current_id + 1:
                            error_cnt += 1
                current_id = packet[-5]
            else:
                other_packets += 1
    return packets_total_from_device, other_packets, error_cnt, packets_total_with_pattern


def print_summary(packets_total_from_device, packets_total_with_pattern, error_cnt, other_packets):
    """"""
    print('        packets total from device  : {}'.format(packets_total_from_device))
    print('        packets total with pattern : {}'.format(packets_total_with_pattern))
    print('        errors with wrong counter  : {}'.format(error_cnt))
    print('        other packets              : {}'.format(other_packets))
    print('')
    return


laptop_pattern = bytes((222, 173, 190, 239))  # 0xDEADBEEF
laptop_mac = bytes((188, 238, 123, 41, 18, 48))  # 0xBCEE7B291230
max10_pattern = bytes((186, 173, 186, 173))  # 0xBAADBAAD
max10_mac = bytes((1, 35, 69, 103, 137, 171))  # 0x0123456789ABC

start_time = time.time()
print('start receiving')
received_packets = sc.sniff(iface='Realtek PCIe GBE Family Controller')

stop_time = time.time()
packets_total = len(received_packets)
print('stop receiving')
print('receive time: {} seconds'.format(stop_time - start_time))
print('{} packets total:'.format(packets_total))

packets_total_from_device, error_pattern, error_cnt, packets_total_with_pattern = receiving(max10_pattern,
                                                                                            max10_mac,
                                                                                            received_packets)
print('    max10 (injected): ')
print_summary(packets_total_from_device, packets_total_with_pattern, error_cnt, error_pattern)


packets_total_from_device, error_pattern, error_cnt, packets_total_with_pattern = receiving(laptop_pattern,
                                                                                            laptop_mac,
                                                                                            received_packets)
print('    laptop (main): ')
print_summary(packets_total_from_device, packets_total_with_pattern, error_cnt, error_pattern)
