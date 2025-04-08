import socket
import sys
import threading
import time
import struct
import os

# Globálna premenná na uloženie poslednej správy, toto pole bude obsahovať fragmenty správy bez chýb
last_message = []
# Event aby send_messages čakal kým bude prenos dokončený
ack_received = threading.Event()

class Flags:
    SYN_MASK = 0b0000001
    ACK_MASK = 0b0000010
    HRT_MASK = 0b0000100
    NAK_MASK = 0b0001000
    FIN_MASK = 0b0010000
    FIL_MASK = 0b0100000
    MSG_MASK = 0b1000000

    def __init__(self):
        self.flag_bits = 0  # Inicializácia na 0

    def set_flag(self, mask):
        self.flag_bits |= mask  # Špecifický flag setne na 1

    def clear_flag(self, mask):
        self.flag_bits &= ~mask  # Špecifický flag setne na 0

    def is_flag_set(self, mask):
        return bool(self.flag_bits & mask)  # Pozrie ako je flag setnutý

def handshake(source_ip, target_ip, send_port, receive_port, num_of_shakes, connection, snd_socket, terminate):
    if send_port < receive_port:
        #Začne merať čas, keď prejde 20 sekúnd a stále nebolo spojenie nadviazané -> ukončí sa
        start_time = time.time()
        
        while connection[0] == 0:
            if num_of_shakes[0] > 0:
                break
            elapsed_time = time.time() - start_time
            if elapsed_time > 20:
                terminate[0] = True
                break

            flags = Flags()
            flags.set_flag(Flags.SYN_MASK)  # Nastaví SYN flag

            # Posielame SYN flag
            snd_socket.sendto(bytes([flags.flag_bits]), (target_ip, send_port))
            time.sleep(0.1)
        
        if not connection[0]:
            print("Spojenie sa nepodarilo nadviazať, ukončujem...")
            terminate[0] = True

def receive_messages(missed_hrt, receive_port, num_of_shakes, connection, target_ip, source_ip, send_port, snd_socket, terminate):
    rec_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rec_socket.bind((source_ip, receive_port))
    rec_socket.settimeout(30)
    file_name = None
    received_fragments = {}
    total_fragments = 0
    err_frags = []
    fragment_size_known = False
    total_message_size = 0
    missing_fragments = []

    while not terminate[0]:
        try:
            data, addr = rec_socket.recvfrom(1500)
            flags_received = data[0]  
            message_data = data[1:]

            flags = Flags()
            flags.flag_bits = flags_received

            if flags.is_flag_set(Flags.NAK_MASK):  # Ak dostaneme NAK
                print("Opätovné odosielanie chybných fragmentov.")
                
                # Extrahujeme počet chybných fragmentov
                nak_data = message_data
                num_err_fragments = struct.unpack('!I', nak_data[:4])[0]  # Počet chybných fragmentov
                err_frag_indices = []  # Zoznam indexov chybných fragmentov
                
                # Načítame čísla chybných fragmentov
                for i in range(num_err_fragments):
                    frag_num = struct.unpack('!I', nak_data[4 + i * 4:8 + i * 4])[0]
                    err_frag_indices.append(frag_num - 1)  # Pre indexovanie od 0 odpočítame 1
                
                # Odosielanie chybných fragmentov
                # last_message je zoznam fragmentov, z ktorého posielame
                for frag_index in err_frag_indices:
                    fragment = last_message[frag_index]
                    adler_checksum = checksum(fragment)

                    # Zabalenie fragmentu s indexom a checksumom
                    flags = Flags()
                    fragment_with_info = struct.pack('!I', frag_index + 1)  # Posielame index fragmentu (1-based)
                    fragment_with_info += struct.pack('!I', len(fragment)) + fragment  # Dĺžka fragmentu + samotný fragment

                    formatted_message = bytes([flags.flag_bits]) + struct.pack('!I', adler_checksum) + fragment_with_info

                    # Odoslanie fragmentu
                    snd_socket.sendto(formatted_message, (target_ip, send_port))
                    print(f"Posielam fragment č. {frag_index + 1} (checksum: {adler_checksum})")

            elif flags.is_flag_set(Flags.ACK_MASK) and not flags.is_flag_set(Flags.HRT_MASK) and not flags.is_flag_set(Flags.SYN_MASK) and num_of_shakes[0] > 1:
                # Setneme príznak aby sme vedeli že môžme znova posielať
                ack_received.set()
            elif flags.is_flag_set(Flags.FIL_MASK):
                fragment_index = 0  # Inicializácia indexu fragmentu

                if file_name is None:  # Detekcia názvu súboru
                    adler_checksum = struct.unpack('!I', message_data[:4])[0]
                    file_name = message_data[4:].decode(errors='ignore')
                    print(f"Prijatý názov súboru: {file_name} checksum: {adler_checksum}")
                    fragment_index += 1  # Zvyšujeme index po prijatí názvu súboru
                    start_time = time.time()

                else:
                    if flags.is_flag_set(Flags.FIN_MASK):
                            flags.clear_flag(Flags.FIN_MASK)
                            # Keď dostaneme FIN flag identifikujeme chýbajúce fragmenty
                            missing_fragments = [
                                i for i in range(1, total_fragments + 1) if i not in received_fragments and i not in err_frags
                            ]
                            if missing_fragments:
                                # Pridanie chýbajúcich fragmentov do zoznamu chybných fragmentov
                                err_frags.extend(missing_fragments)
                    else:
                        # Unpackneme dáta o fragmente
                        adler_checksum = struct.unpack('!I', message_data[:4])[0]
                        total_fragments = struct.unpack('!I', message_data[4:8])[0]
                        fragment_number = struct.unpack('!I', message_data[8:12])[0]
                        fragment_size = struct.unpack('!I', message_data[12:16])[0]
                        fragment_data = message_data[16:]

                        # Podľa checksumu zistíme či je fragment korektný. ak nie pridáme ho do zoznamu chybných fragmentov
                        calculated_checksum = checksum(fragment_data.decode(errors="ignore"))
                        if adler_checksum != calculated_checksum:
                            err_frags.append(fragment_number)
                            print(f"Chybný fragment č. {fragment_number}!")
                        else:
                            received_fragments[fragment_number] = fragment_data
                            total_message_size += fragment_size
                            print(f"Fragment č. {fragment_number} bol prijatý správne.")
                            if total_fragments == 0:
                                total_fragments = total_fragments

                    # Ak sú všetky fragmenty prijaté
                    if len(received_fragments) + len(err_frags) == total_fragments:
                        if err_frags:
                            # Odoslanie NAK so zoznamom chybných fragmentov
                            print("Chybné fragmenty detekované. Odosielam NAK...")
                            flags.set_flag(Flags.NAK_MASK)
                            nak_message = bytes([flags.flag_bits]) + struct.pack('!I', len(err_frags))
                            for frag_num in err_frags:
                                nak_message += struct.pack('!I', frag_num)
                            snd_socket.sendto(nak_message, (target_ip, send_port))
                            flags.clear_flag(Flags.NAK_MASK)

                            # Čakanie na opravené fragmenty
                            print("Čakám na opravené fragmenty...")
                            while err_frags:
                                try:
                                    data, addr = rec_socket.recvfrom(1500)
                                    flags_received = data[0]
                                    message_data = data[1:]

                                    flags = Flags()
                                    flags.flag_bits = flags_received

                                    if len(message_data) >= 8:
                                        adler_checksum = struct.unpack('!I', message_data[:4])[0]
                                        fragment_index = struct.unpack('!I', message_data[4:8])[0]

                                        if fragment_index in err_frags:
                                            fragment_size = struct.unpack('!I', message_data[8:12])[0]
                                            fragment = message_data[12:]

                                            calculated_checksum = checksum(fragment)
                                            if adler_checksum == calculated_checksum:
                                                received_fragments[fragment_index] = fragment
                                                err_frags.remove(fragment_index)
                                                print(f"Fragment č. {fragment_index} bol opravený a prijatý správne.")
                                            else:
                                                print(f"Fragment č. {fragment_index} stále obsahuje chybu.")
                                except socket.timeout:
                                    print("Čakanie na opravené fragmenty vypršalo. Opätovné odoslanie NAK...")
                                    flags.set_flag(Flags.NAK_MASK)
                                    snd_socket.sendto(nak_message, (target_ip, send_port))
                                    flags.clear_flag(Flags.NAK_MASK)
                                except struct.error as e:
                                    print(f"Chyba pri spracovaní dát: {e}")

                            print("Všetky chybné fragmenty boli opravené.")

                        # Ak už nie sú žiadne chyby, uloženie súboru
                        file_path = os.path.join(output_path, file_name).replace('\x00', '')
                        with open(file_path, 'wb') as output_file:
                            for i in range(1, total_fragments + 1):
                                output_file.write(received_fragments[i])

                        file_size_kb = total_message_size / 1024
                        print(f"Súbor '{file_name}' | Veľkosť: {file_size_kb:.2f} kB bol úspešne prijatý a uložený na:\n{file_path}")
                        end_time = time.time()
                        print(f"Trvanie prenosu: {(end_time - start_time):.2f} s")
                        # Poslanie ACK
                        flags.set_flag(Flags.ACK_MASK)
                        snd_socket.sendto(bytes([flags.flag_bits]), (target_ip, send_port))
                        flags.clear_flag(Flags.ACK_MASK)

                        # Resetovanie stavu
                        received_fragments.clear()
                        total_fragments = 0
                        err_frags.clear()
                        fragment_size_known = False
                        file_name = None
                        total_message_size = 0

            elif flags.is_flag_set(Flags.MSG_MASK):

                if not fragment_size_known:
                    # Prvý fragment nesie zo sebou aj počet celkových fragmentov, preto ho spracujeme inak
                    if len(message_data) >= 12:
                        if flags.is_flag_set(Flags.FIN_MASK):
                            flags.clear_flag(Flags.FIN_MASK)
                            
                            # Keď dostaneme FIN flag identifikujeme chýbajúce fragmenty
                            missing_fragments = [
                                i for i in range(1, total_fragments + 1) if i not in received_fragments
                            ]
                            if missing_fragments:
                                # Pridanie chýbajúcich fragmentov do zoznamu chybných fragmentov
                                err_frags.extend(missing_fragments)
                        else:
                            adler_checksum = struct.unpack('!I', message_data[:4])[0]
                            num_fragments = struct.unpack('!I', message_data[4:8])[0]
                            fragment_number = struct.unpack('!I', message_data[8:12])[0]
                            fragment_size = struct.unpack('!I', message_data[12:16])[0]
                            fragment = message_data[16:]
                            fragment_size_known = True
                            start_time = time.time()
                    else:
                        continue
                # Ostatné fragmenty
                else:
                    if flags.is_flag_set(Flags.FIN_MASK):
                        flags.clear_flag(Flags.FIN_MASK)
                        
                        # Keď dostaneme FIN flag identifikujeme chýbajúce fragmenty
                        missing_fragments = [
                            i for i in range(1, total_fragments + 1) if i not in received_fragments
                        ]
                        if missing_fragments:
                            # Pridanie chýbajúcich fragmentov do zoznamu chybných fragmentov
                            err_frags.extend(missing_fragments)

                    else:
                        adler_checksum = struct.unpack('!I', message_data[:4])[0]
                        fragment_number = struct.unpack('!I', message_data[4:8])[0]
                        fragment_size = struct.unpack('!I', message_data[8:12])[0]
                        fragment = message_data[12:]
                
                # Ak fragment nechýba, skontrolujem či je korektný
                if len(missing_fragments)==0:
                    total_message_size += fragment_size
                    print(f"Prijatý fragment {fragment_number}: {fragment.decode()} (Veľkosť: {fragment_size} bajtov)")

                    if total_fragments == 0:
                        total_fragments = num_fragments

                    calculated_checksum = checksum(fragment.decode())

                    if adler_checksum != calculated_checksum:
                        err_frags.append(fragment_number)
                        print(f"Chybný fragment č. {fragment_number}!")

                    # Uloží fragment podľa jeho fragment_number
                    received_fragments[fragment_number] = fragment.decode()

                # Keď už bolo posielanie ukončené, pozrieme či máme ešte nejaké chyby, ak nie -> môžme vypísať správu
                if len(received_fragments) + len(missing_fragments) == total_fragments:
                    reconstructed_message = "".join([received_fragments[i] for i in sorted(received_fragments.keys())])
                    if not err_frags:
                        print(f"IP: {addr[0]}, Port: {addr[1]}\nSpráva: {reconstructed_message}")
                        print(f"Velkosť správy: {total_message_size + len(missing_fragments)} bajtov")
                        end_time = time.time()
                        print(f"Trvanie prenosu: {(end_time - start_time):.2f} s")

                    # Ak áno pošleme NAK a čakáme na opätovné prijatie chybných fragmentov
                    if err_frags:
                        print("Správa obsahuje chybné alebo nedoručené fragmenty. Odosielam NAK")
                        flags.set_flag(Flags.NAK_MASK)
                        nak_message = bytes([flags.flag_bits]) + struct.pack('!I', len(err_frags))
                        for frag_num in err_frags:
                            nak_message += struct.pack('!I', frag_num)
                        snd_socket.sendto(nak_message, (target_ip, send_port))
                        flags.clear_flag(Flags.NAK_MASK)

                        # Čakanie na opätovné prijatie chybných fragmentov
                        while err_frags:
                            try:
                                # Pokus o prijatie opraveného fragmentu
                                data, addr = rec_socket.recvfrom(1500)
                                flags_received = data[0]
                                message_data = data[1:]

                                flags = Flags()
                                flags.flag_bits = flags_received

                                # Spracovanie prijatého fragmentu
                                if len(message_data) >= 8:
                                    adler_checksum = struct.unpack('!I', message_data[:4])[0]
                                    fragment_index = struct.unpack('!I', message_data[4:8])[0]  # Index fragmentu

                                    if fragment_index in err_frags:
                                        # Ak je prijatý chybný fragment
                                        fragment_size = struct.unpack('!I', message_data[8:12])[0]
                                        fragment = message_data[12:]

                                        calculated_checksum = checksum(fragment.decode())
                                        if adler_checksum == calculated_checksum:
                                            # Ak je fragment správny, aktualizuj v received_fragments
                                            received_fragments[fragment_index] = fragment.decode()
                                            err_frags.remove(fragment_index)
                                            print(f"Fragment č. {fragment_index} bol opravený a prijatý správne.")
                                        else:
                                            print(f"Fragment č. {fragment_index} stále obsahuje chybu.")
                                    else:
                                        print(f"Prijatý fragment č. {fragment_index}, ktorý nebol označený ako chybný.")
                                        print(f"{fragment_index-1}")
                            except socket.timeout:
                                print("Čakanie na opravené fragmenty vypršalo. Opätovné odoslanie NAK...")
                                flags.set_flag(Flags.NAK_MASK)
                                snd_socket.sendto(nak_message, (target_ip, send_port))
                                flags.clear_flag(Flags.NAK_MASK)
                            except struct.error as e:
                                print(f"Chyba pri spracovaní dát: {e}")

                        print("Všetky chybné alebo nedoručené fragmenty boli opravené.")
                        # Rekonštrukcia správy z opravených fragmentov
                        reconstructed_message = "".join([received_fragments[i] for i in sorted(received_fragments.keys())])

                        print(f"IP: {addr[0]}, Port: {addr[1]}\nOpravená správa: {reconstructed_message}")
                        print(f"Velkosť správy: {total_message_size + len(missing_fragments)} bajtov")
                        end_time = time.time()
                        print(f"Trvanie prenosu: {(end_time - start_time):.2f} s")

                        flags.set_flag(Flags.ACK_MASK)
                        snd_socket.sendto(bytes([flags.flag_bits]), (target_ip, send_port))
                        flags.clear_flag(Flags.ACK_MASK)
                    else:
                        print("Správa je správna")
                        flags.set_flag(Flags.ACK_MASK)
                        snd_socket.sendto(bytes([flags.flag_bits]), (target_ip, send_port))
                        flags.clear_flag(Flags.ACK_MASK)

                    received_fragments.clear()
                    total_fragments = 0
                    err_frags.clear()
                    fragment_size_known = False
                    total_message_size = 0
                    missing_fragments = []

            elif flags.is_flag_set(Flags.FIN_MASK) and not flags.is_flag_set(Flags.MSG_MASK) and not flags.is_flag_set(Flags.FIL_MASK):
                # Ak nám príde samotný FIN flag, považujeme spojenie za ukončené
                print("Druhý klient ukončil spojenie")
                rec_socket.close()
                snd_socket.close()
                connection[0] = False
                terminate[0] = True
                break

            elif flags.is_flag_set(Flags.SYN_MASK) and not flags.is_flag_set(Flags.ACK_MASK) and num_of_shakes[0] == 0:
                # Príde nám SYN -> odosielame SYN | ACK
                flags.set_flag(Flags.ACK_MASK)
                snd_socket.sendto(bytes([flags.flag_bits]), (target_ip, send_port))
                num_of_shakes[0] += 1
            elif flags.is_flag_set(Flags.SYN_MASK) and flags.is_flag_set(Flags.ACK_MASK) and num_of_shakes[0] == 0:
                # Príde nám SYN | ACK -> odosielame ACK
                flags.clear_flag(Flags.SYN_MASK)
                snd_socket.sendto(bytes([flags.flag_bits]), (target_ip, send_port))
                num_of_shakes[0] += 1
                connection[0] = True
                rec_socket.settimeout(None)
            elif flags.is_flag_set(Flags.ACK_MASK) and num_of_shakes[0] == 1:
                # Prišiel nám ACK -> handshake complete
                connection[0] = True
                rec_socket.settimeout(None)
                num_of_shakes[0] += 1
            elif flags.is_flag_set(Flags.HRT_MASK) and not flags.is_flag_set(Flags.ACK_MASK):
                # Príde nám HRT -> odosielame HRT | ACK
                flags.set_flag(Flags.ACK_MASK)
                flags.set_flag(Flags.HRT_MASK)
                snd_socket.sendto(bytes([flags.flag_bits]), (target_ip, send_port))
            elif flags.is_flag_set(Flags.ACK_MASK) and flags.is_flag_set(Flags.HRT_MASK):
                # Príde nám HRT | ACK -> heartbeat úspešný
                connection[0] = True
                missed_hrt[0] = -1
        except socket.timeout:
            print("Spojenie sa nepodarilo nadviazať, ukončujem...")
            rec_socket.close()
            snd_socket.close()
            connection[0] = False
            terminate[0] = True
            break
        except struct.error as e:
            print("")

def checksum(message):
    if isinstance(message, bytes):
        # Ak nám prídu bajty -> dekódujeme ich na znaky
        message = message.decode('utf-8', errors='ignore')
    # Inicializácia hodnôt A a B
    A = 1
    B = 0
    MOD_ADLER = 65521  # Najväčšie prvočíslo menšie ako 2^16

    # Výpočet hodnôt A a B pre každý znak v správe
    for char in message:
        A = (A + ord(char)) % MOD_ADLER
        B = (B + A) % MOD_ADLER

    # Výpočet výsledného kontrolného súčtu Adler-32
    adler32 = (B << 16) | A  # Posun B o 16 bitov a kombinácia s A

    return adler32  # Return kontrolného súčtu

def send_messages(target_ip, send_port, connection, num_of_shakes, snd_socket, terminate):
    global last_message  # Povolenie používať globálnu premennú
    while not terminate[0]:  # Pokračuj, iba ak nie je nastavená terminácia
        if connection[0] == False and num_of_shakes[0] > 0:
            break  # Ukonči cyklus, ak je spojenie ukončené

        try:
            # Čakaj na prijatie ACK pred ďalším posielaním
            if connection[0]==True and len(last_message)>0:
                ack_received.wait()  # Čaká, kým `ack_received` nebude nastavené
                ack_received.clear()  # Resetuje udalosť na ďalšie použitie

            file_or_message = input("\nPoslať správu(s) | file(f) | pre ukončenie(e):")

            # Ak bol výber e, posielame FIN flag
            if file_or_message == "e":
                print("Ukončujem spojenie")
                flags = Flags()
                flags.set_flag(Flags.FIN_MASK)

                # Odoslanie fragmentu
                snd_socket.sendto(bytes([flags.flag_bits]), (target_ip, send_port))
                terminate[0] = True
                break
            
            while True:
                try:
                    # Získanie veľkosti fragmentu s validáciou vstupu
                    fragment_size = int(input("Zadaj veľkosť fragmentu v bajtoch: "))  # Požiadanie o veľkosť fragmentu
                    if fragment_size <= 0 or fragment_size >= 1456:
                        print("Veľkosť fragmentu musí byť kladné číslo menšie ako 1456. Skús to znova.")
                        continue  # Ak je veľkosť fragmentu nula alebo menej alebo väčšie ako 1455, požiada o nový vstup
                    break  # Ukonči cyklus, ak je vstup platný
                except ValueError:
                    if terminate[0]:  # Ak je nastavený flag na ukončenie, ukonči funkciu
                        break
                    print("Nezadali ste platné číslo. Skús to znova.")
            if terminate[0]:  # Ak je nastavený flag na ukončenie, ukonči funkciu
                        break
            flags = Flags()
            flags.clear_flag(Flags.MSG_MASK)
            flags.clear_flag(Flags.FIL_MASK)
            if file_or_message == "s":
                message = input("\nZadaj správu: ")
                message_size = len(message.encode())  # Veľkosť správy v bajtoch
                
                if terminate[0]:  # Ak je nastavený flag na ukončenie, ukonči funkciu
                    break

                simulate_missing = input("Simulovať chybný alebo chýbajúci fragment? (a/n):")
                
                print(f"Posielam správu: {message} | Veľkosť: {message_size:.2f} bajtov")

                # Rozdelenie správy na fragmenty
                message_bytes = message.encode()
                total_len = len(message_bytes)
                num_fragments = (total_len + fragment_size - 1) // fragment_size  # Výpočet počtu fragmentov

                last_message = []  # Resetovanie globálneho poľa pre novú správu

                for i in range(0, total_len, fragment_size):
                    flags = Flags()
                    # Určenie aktuálneho fragmentu
                    if i + fragment_size >= total_len:
                        fragment = message_bytes[i:]  # Zober iba zvyšok správy
                    else:
                        fragment = message_bytes[i:i + fragment_size]

                    # Výpočet checksum pre každý fragment
                    adler_checksum = checksum(fragment.decode())

                    # Uloženie originálneho fragmentu bez chyby do last_message
                    last_message.append(fragment)

                    # Simulácia chyby podľa výberu používateľa
                    if simulate_missing == "a":
                        simulate_error = input("Simulovať chybný fragment? (a/n): ").strip().lower()
                        if simulate_error == "a":
                            fault_type = input("Zadaj typ chyby d(data)/c(checksum): ").strip().lower()
                            if fault_type == "d":
                                fragment = b"X" + fragment[1:]
                            elif fault_type == "c":
                                adler_checksum += 1
                    

                    # Zabalenie fragmentu s veľkosťou
                    current_fragment_size = len(fragment)  # Skutočná veľkosť fragmentu
                    if i == 0:
                        # Prvý fragment: zahrnutie počtu fragmentov a veľkosti
                        fragment_with_info = struct.pack('!I', num_fragments) + struct.pack('!I', int(i / fragment_size) + 1) + struct.pack('!I', current_fragment_size) + fragment
                    else:
                        # Následné fragmenty: zahrnutie veľkosti fragmentu
                        fragment_with_info = struct.pack('!I', int(i / fragment_size) + 1) + struct.pack('!I', current_fragment_size) + fragment

                    # Príprava formátovanej správy s checksum a fragmentom
                    flags.set_flag(Flags.MSG_MASK)
                    formatted_message = bytes([flags.flag_bits]) + struct.pack('!I', adler_checksum) + fragment_with_info
                    flags.clear_flag(Flags.FIN_MASK)

                    # Odoslanie fragmentu
                    if simulate_missing == "n":
                        snd_socket.sendto(formatted_message, (target_ip, send_port))
                        print(f"Posielam fragment {i // fragment_size + 1}/{num_fragments}: {fragment.decode()} | veľkosť: {current_fragment_size} bajtov")
                    # Ak simulujeme stratený fragment vynecháme fragment číslo 2
                    if simulate_missing == "a":
                        if not ((i / fragment_size) + 1) == 2:
                            snd_socket.sendto(formatted_message, (target_ip, send_port))
                            print(f"Posielam fragment {i // fragment_size + 1}/{num_fragments}: {fragment.decode()} | veľkosť: {current_fragment_size} bajtov")
                # Odoslanie FIN a MSG flagu, aby sme informovali druhú stranu o ukončení posielania rejto správy
                flags.set_flag(Flags.FIN_MASK)
                flags.set_flag(Flags.MSG_MASK)
                snd_socket.sendto(bytes([flags.flag_bits]), (target_ip, send_port))
                flags.clear_flag(Flags.FIN_MASK)
                flags.clear_flag(Flags.MSG_MASK)
            if file_or_message == "f":
                file_path = input("Zadaj cestu k súboru: ")
                
                # Získanie názvu súboru
                file_name = os.path.basename(file_path)
                
                # Získanie veľkosti súboru
                file_size = os.path.getsize(file_path)  # Veľkosť v bajtoch
                file_size_kb = file_size / 1024  # Prevod na kB
                
                # Odoslanie názvu súboru ako samostatný fragment
                flags = Flags()
                flags.set_flag(Flags.FIL_MASK)  # Nastavíme flag pre file transfer
                file_name_fragment = struct.pack('!I', 0) + file_name.encode()  # Fragment so špeciálnym indexom 0 pre názov súboru
                formatted_file_name = bytes([flags.flag_bits]) + struct.pack('!I', checksum(file_name)) + file_name_fragment
                
                snd_socket.sendto(formatted_file_name, (target_ip, send_port))
                
                try:
                    with open(file_path, 'rb') as file:
                        # Počet fragmentov pre obsah súboru
                        fragment_count = (file_size + fragment_size - 1) // fragment_size
                        is_faulty = input("Simulovať chybné fragmenty?(a/n):")
                        is_missing = input("Simulovať nedoručený frgment?(a/n):")
                        last_message = []  # Reset globálnej premennej pre fragmenty

                        for i in range(fragment_count):
                            time.sleep(0.001)
                            # Načítanie fragmentu zo súboru
                            fragment = file.read(fragment_size)
                            if not fragment:
                                break  # Ukonči cyklus, ak súbor skončil
                            
                            # Kontrola veľkosti fragmentu (posledný fragment môže byť menší)
                            current_fragment_size = len(fragment)

                            adler_checksum = checksum(fragment.decode(errors='ignore'))
                            # Uloženie originálneho fragmentu do `last_message`
                            last_message.append(fragment)

                            if is_faulty == "a" and (i == 100 or i == 2744):  # Simulácia chyby
                                adler_checksum += 1

                            # Zabalenie metadát a fragmentu
                            fragment_with_info = struct.pack('!I', fragment_count) + struct.pack('!I', i + 1) + struct.pack('!I', current_fragment_size) + fragment

                            # Príprava formátovanej správy
                            formatted_message = bytes([flags.flag_bits]) + struct.pack('!I', adler_checksum) + fragment_with_info

                            # Ak simulujeme stratený fragment, fragment číslo 2745 sa neodošle
                            if is_missing == "a":
                                if not i == 2745:
                                    snd_socket.sendto(formatted_message, (target_ip, send_port))
                                    print(f"Posielam fragment {i + 1}/{fragment_count} | Veľkosť: {current_fragment_size} bajtov")
                            if is_missing == "n":
                                snd_socket.sendto(formatted_message, (target_ip, send_port))
                                print(f"Posielam fragment {i + 1}/{fragment_count} | Veľkosť: {current_fragment_size} bajtov")

                    # Odoslanie FIN a FIL flagu, aby sme informovali druhú stranu o ukončení posielania tohto súboru
                    flags.set_flag(Flags.FIN_MASK)
                    flags.set_flag(Flags.FIL_MASK)
                    snd_socket.sendto(bytes([flags.flag_bits]), (target_ip, send_port))
                    flags.clear_flag(Flags.FIN_MASK)
                    flags.clear_flag(Flags.FIL_MASK)

                    print(f"Úspešne bol poslaný súbor: {file_name} | Veľkosť: {file_size_kb:.2f} kB")
                except FileNotFoundError:
                    print(f"Súbor na ceste '{file_path}' neexistuje. Skontroluj cestu a skús znova.")
                except OSError as e:
                    print(f"Chyba pri práci so súborom: {e}")
        
        except OSError:
            # Ošetrenie prípadu, keď je soket zatvorený
            print("Soket bol zatvorený, ukončujem send_messages.")
            break

def send_heartbeat(missed_hrt, target_ip, send_port, connection, snd_socket, terminate):
    while connection[0] and not terminate[0]:  # Pokračuje v posielaní, kým je spojenie aktívne
        flags = Flags()
        flags.set_flag(Flags.HRT_MASK)  # Nastavenie HRT flagu

        # Posielame HRT flag
        heartbeat_message = bytes([flags.flag_bits])

        # Odoslanie heartbeat správy
        snd_socket.sendto(heartbeat_message, (target_ip, send_port))

        missed_hrt[0] += 1
        if missed_hrt[0] >= 5:
            print("Druhý klient neodpovedá, ukončujem spojenie...")
            terminate[0] = True
        time.sleep(5)  # Počká 5 sekúnd pred ďalším odoslaním

if __name__ == "__main__":
    source_ip = "169.254.132.130"
    target_ip = input("IP druhého klienta: ")
    send_port = int(input("Na ktorý port posielam: "))
    receive_port = int(input("Na ktorom porte počúvam: "))
    output_path = input("Kde budem ukladať súbory?:")
    if output_path == "":
        output_path = os.getcwd()
    num_of_shakes = [0]  # Počet "potrasení" -> aby sme dosiahli 3 way handshake
    connection = [False] # Príznak či máme aktívne spojenie
    terminate = [False]  # Príznak na ukončenie programu
    missed_hrt = [0]     # Počet HRT flagov na ktoré sme nedostali ACK

    # Nastavenie sending portu
    snd_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    snd_socket.bind((source_ip, 3))# <- Z tohto portu posielam, ak testujem na tom istom zariadení, treba jeden zmeniť

    # Spustenie threadu na príjmanie správ
    receive_thread = threading.Thread(target=receive_messages, args=(missed_hrt, receive_port, num_of_shakes, connection, target_ip, source_ip, send_port, snd_socket, terminate))
    receive_thread.daemon = True
    receive_thread.start()

    # Začne sa vykonávať handshake
    handshake(source_ip, target_ip, send_port, receive_port, num_of_shakes, connection, snd_socket, terminate)
    
    while connection[0] == False and not terminate[0]:
        time.sleep(1)
    
    if connection[0] and not terminate[0]:  # Spustí heartbeat len ak bolo spojenie úspešne nadviazané
        heartbeat_thread = threading.Thread(target=send_heartbeat, args=(missed_hrt, target_ip, send_port, connection, snd_socket, terminate))
        heartbeat_thread.daemon = True
        heartbeat_thread.start()

    if connection[0]==True:
        print("Spojenie nadviazané")
    send_messages(target_ip, send_port, connection, num_of_shakes, snd_socket, terminate)
    
    if terminate[0]:  # Ukončí program, ak je nastavený príznak terminate
        sys.exit()
