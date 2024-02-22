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

#ifndef __IDA_ARCH_H
#define __IDA_ARCH_H

#include <map>
#include <vector>
#include <sstream>
#include <string.h>

#include "architecture.hh"
#include "sleigh_arch.hh"
#include "xml.hh"
#include "address.hh"
#include "database.hh"

#include "plugin.hh"
#include "ida_minimal.hh"

using ghidra::SleighArchitecture;
using ghidra::DocumentStorage;
using ghidra::Scope;
using ghidra::Symbol;
using ghidra::Address;


class ida_arch : public SleighArchitecture {

public:
   ida_arch(const string &fname,const string &targ,ostream *estream) : SleighArchitecture(fname, targ, estream) {};

protected:
   /// \brief Build the LoadImage object and load the executable image
   ///
   /// \param store may hold configuration information
   virtual void buildLoader(DocumentStorage &store);

   // Factory routines for building this architecture
   virtual Scope *buildDatabase(DocumentStorage &store); ///< Build the global scope for this executable

   virtual void postSpecFile(void);		///< Let components initialize after Translate is built

   Symbol *getSymbol(const Address &addr);

};

#endif
