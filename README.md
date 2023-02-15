# The CRAM Model Sample Implementations

## Instructions:
1. Navigate to: https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md
2. Download the 2022-Nov-01, Ubuntu 20.04, 2.3 GBytes VM image
3. Import the VM image into VirtualBox 6.1.40 on Windows 10
4. Clone this Git repository into /home/p4
5. Copy the bsic and resail directories into /home/p4/tutorials/exercises
```bash
cd ~
cp -r cram/bsic/ tutorials/exercises/
cp -r cram/resail/ tutorials/exercises/
```
6. Generate the control plane files
```bash
cd /home/p4/tutorials/exercises/bsic/
mkdir sim-topo
python3 bsicgen.py ipv6.txt (may take around 10 minutes)
mv *.json sim-topo/
cd /home/p4/tutorials/exercises/resail/
mkdir sim-topo
python3 resailgen.py ipv4.txt
mv *.json sim-topo/
```
7. Compile and run the P4 code
```bash
cd /home/p4/tutorials/exercises/bsic/
make run
```
```bash
cd /home/p4/tutorials/exercises/resail/
make run (may take around 10 minutes)
```
8. Launch xterm windows for testing
```bash
xterm h1 h2 h3 h4 h5
```
9. Send and receive packets
#### On h2, h3, h4, and h5:
```bash
./receive.py
```
#### On h1:
```bash
./send.py ip_address "data"
```

## BSIC Additional Step (run between steps 6 and 7):
1. Move updated utility files into their proper locations
```bash
cd ~
rm tutorials/utils/p4_mininet.py
cp cram/p4_mininet.py tutorials/utils/
rm tutorials/utils/p4runtime_lib/convert.py
cp cram/convert.py tutorials/utils/p4runtime_lib/
```
