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

#include <map>
#include <vector>
#include <sstream>
#include <string.h>
#include "xml.hh"
#include "address.hh"
#include "funcdata.hh"

#include "ida_arch.hh"
#include "ida_scope.hh"
#include "plugin.hh"
#include "ida_minimal.hh"
#include "ida_load_image.hh"

using ghidra::Database;

/// \brief Build the LoadImage object and load the executable image
///
/// \param store may hold configuration information
void ida_arch::buildLoader(DocumentStorage &store) {
   collectSpecFiles(*errorstream);
   loader = new ida_load_image(this);
}

void ida_arch::postSpecFile(void) {
/*
   size_t nfuncs = get_func_qty();
   for (size_t i = 0; i < nfuncs; i++) {
      void *f = getn_func(i);
      uint64_t func_ea = get_func_start(f);
      if (!does_func_return(f)) {
         Funcdata *infd = symboltab->getGlobalScope()->queryFunction(Address(getDefaultSpace(), func_ea));
         infd->getFuncProto().setNoReturn(true);
      }
   }
*/
}

Scope *ida_arch::buildDatabase(DocumentStorage &store) {
//   msg("ida_arch::buildDatabase\n");
   symboltab = new Database(this, true);
   Scope *globscope = new ida_scope(0, this);
   symboltab->attachScope(globscope, NULL);
   return globscope;
}

Symbol *ida_arch::getSymbol(const Address &addr) {
//   msg("ida_arch::getSymbol - 0x%llx\n", (uint64_t)addr.getOffset());
   return NULL;
}
