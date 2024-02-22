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

#ifndef __IDA_LOAD_IMAGE_H
#define __IDA_LOAD_IMAGE_H

#include <string>

// Windows defines LoadImage to LoadImageA
#ifdef LoadImage
#undef LoadImage
#endif

#include "loadimage.hh"
#include "ida_arch.hh"

using ghidra::LoadImage;

using std::string;

/// \brief An implementation of the LoadImage interface using IDA as the back-end
///
/// Requests for program bytes are marshalled to IDA which sends back the data

class ida_load_image : public LoadImage {
  ida_arch *arch;       ///< The owning Architecture and connection to the client
public:
  ida_load_image(ida_arch *a); ///< Constructor
  void loadFill(uint1 *ptr, int4 size, const Address &addr);
  string getArchType(void) const;
  void adjustVma(long adjust);
};

#endif
