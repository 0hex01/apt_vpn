CXX      := g++
CXXFLAGS := -O2 -Wall -std=c++17 $(shell pkg-config --cflags gtk+-3.0)
LDLIBS   := $(shell pkg-config --libs gtk+-3.0) -lssl -lcrypto
FOLDERS  := udp tcp secure_udp secure_tcp wireguard_files

vpn-manager: src/main.cpp src/embedded_data.h src/countries.h
	$(CXX) $(CXXFLAGS) -o vpn-manager src/main.cpp $(LDLIBS)

# Pack the vpn config folders into a C array (gzipped tar)
src/embedded_data.h: $(FOLDERS)
	tar czf - $(FOLDERS) | xxd -i -n vpn_files_data > $@

clean:
	rm -f vpn-manager src/embedded_data.h

.PHONY: clean
