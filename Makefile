#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#	    
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#			    
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#

APXS=apxs2
APXS_OPTS=-Wc, -Wc,-DDST_CLASS=3
SRC=src/mod_spamhaus_new.c
OBJ=src/.libs/mod_spamhaus_new.so

$(OBJ): $(SRC)
	@echo 
	$(APXS) $(APXS_OPTS) -c $(SRC)
	@echo
	@echo write '"make install"' to install module
	@echo

install: $(OBJ)
	$(APXS) $(APXS_OPTS) -i -a -n spamhaus_new src/mod_spamhaus_new.la

clean:
	rm -f src/.libs/*
	rm -f src/*.o
	rm -f src/*.lo
	rm -f src/*.la
	rm -f src/*.slo
	rmdir src/.libs
