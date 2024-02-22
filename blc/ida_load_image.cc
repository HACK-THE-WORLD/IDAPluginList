/*
   Source for the blc IdaPro plugin
   Copyright (c) 2019 Chris Eagle

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
   more details.

   You should have received a copy of the GNU General Public License along with
   this program; if not, write to the Free Software Foundation, Inc., 59 Temple
   Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include "ida_minimal.hh"

// Windows defines LoadImage to LoadImageA
#ifdef LoadImage
#undef LoadImage
#endif

#include "ida_load_image.hh"

using ghidra::LowlevelError;

ida_load_image::ida_load_image(ida_arch *a) : LoadImage("ida_progam") {
  arch = a;
}

void ida_load_image::loadFill(uint1 *ptr, int4 size, const Address &inaddr) {
   get_bytes(ptr, size, inaddr.getOffset());
}

string ida_load_image::getArchType(void) const {
   return "ida";
}

void ida_load_image::adjustVma(long adjust) {
   throw LowlevelError("Cannot adjust IDA virtual memory");
}
