#
# Makefile for swifi.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile...

# All of the (potential) objects that export symbols.
# This list comes from 'grep -l EXPORT_SYMBOL *.[hc]'.

swifi-objs := db_sym.o random.o fault_model.o \
	udis86.o decode.o itab.o swifi_dev.o

obj-$(CONFIG_SWIFI) += swifi.o
