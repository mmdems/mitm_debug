import scapy.all as sc
import time
import random


def sending(pattern, pck_len_low=80, pck_len_high=250, inter_low=2750e-9, inter_high=3250e-9):
    """"""
    print('')
    print('start sending')
    total, id = 0, 0
    while True:
        try:
            packet = [255] * random.randint(pck_len_low, pck_len_high)
            packet.append(id)
            packet.extend(pattern)
            packet = bytes(packet)
            sc.send(packet, inter=random.uniform(inter_low, inter_high), verbose=False)
            total += 1
            if id == 255:
                id = 0
            else:
                id += 1
        except KeyboardInterrupt:
            break
    return total


# (222, 173, 190, 239) = "0xDEADBEEF"
start_time = time.time()
total = sending((222, 173, 190, 239))
print('')
print('stop sending')
print('time of sending : {} seconds'.format(time.time() - start_time))
print('total           : {}'.format(total))
print(''.format(total))
