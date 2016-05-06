TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    arpspoofing.cpp

LIBS += -lpcap
LIBS += -lnet
LIBS += -lpthread

HEADERS += \
    arpspoofing.h \
