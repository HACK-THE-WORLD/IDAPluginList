/*
   Source for blc IdaPro plugin
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

#ifndef __IDA_SCOPE_H
#define __IDA_SCOPE_H

#include <map>
#include <vector>
#include <sstream>
#include <string.h>
#include "address.hh"
#include "funcdata.hh"
#include "database.hh"

#include "ida_arch.hh"
#include "plugin.hh"
#include "ida_minimal.hh"
#include "ida_load_image.hh"

using ghidra::ScopeInternal;
using ghidra::SymbolEntry;
using ghidra::Datatype;
using ghidra::Funcdata;
using ghidra::ExternRefSymbol;
using ghidra::LabSymbol;

/// \brief An implementation of the Scope interface by querying a ida client for Symbol information
///
/// This object is generally instantiated once for an executable and
/// acts as the \e global \e scope for the decompiler.
/// This object fields queries for all scopes above functions.
/// Responses may be for Symbol objects that are not global but belong to sub-scopes,
/// like \e namespace and function Scopes.  This object will build any new Scope or Funcdata,
/// object as necessary and stick the Symbol in, returning as if the new Scope
/// had caught the query in the first place.
class ida_scope : public ScopeInternal {
   ida_arch *ida;    ///< Architecture and connection to the ida client
   Symbol *ida_query(const Address &addr) const;    ///< Process a query that missed the cache
public:
   ida_scope(uint64_t id, ida_arch *g); ///< Constructor

   virtual ~ida_scope(void);
   virtual SymbolEntry *addSymbol(const string &name, Datatype *ct,
                                  const Address &addr, const Address &usepoint);
   virtual string buildVariableName(const Address &addr,
                                    const Address &pc,
                                    Datatype *ct, int4 &index, uint4 flags) const;
   virtual string buildUndefinedName(void) const;

   virtual SymbolEntry *findAddr(const Address &addr, const Address &usepoint) const;
   virtual SymbolEntry *findContainer(const Address &addr, int4 size,
               const Address &usepoint) const;
   virtual Funcdata *findFunction(const Address &addr) const;
   virtual ExternRefSymbol *findExternalRef(const Address &addr) const;
   virtual LabSymbol *findCodeLabel(const Address &addr) const;
   virtual Funcdata *resolveExternalRefFunction(ExternRefSymbol *sym) const;

   virtual void findByName(const string &name, vector<Symbol *> &res) const;

};

#endif
