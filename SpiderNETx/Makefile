TARGET = SpiderNet

CXX = g++
CXXFLAGS = -Wall -std=c++11 -I. -I./app/h -I./DOS/h -I./fingerprint/h -I./ping/h -I./scanner/h
LDFLAGS = -lpthread

SRCS = app/main.cpp \
       app/App.cpp \
       DOS/Dos.cpp \
       fingerprint/Fingerprint.cpp \
       ping/Ping.cpp \
       ping/IpResponse.cpp \
       scanner/Scanner.cpp

OBJS = $(SRCS:.cpp=.o)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

#
run:
	sudo ./$(TARGET)