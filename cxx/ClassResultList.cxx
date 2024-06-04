/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDED_cxx_ClassResultList_cxx
#define INCLUDED_cxx_ClassResultList_cxx
#include "ClassResultList.hxx" /* ResultList ResultListBytecode*/
#include "ClassSha2.hxx" /* Sha2 */
namespace Susuwu {
const bool resultListHashesHas(const ResultList &list, ResultList &caches, const ResultListBytecode &bytecode) {
	auto bytecodeSha2 = Sha2(bytecode);
	if(listHas(caches.hashes, bytecodeSha2)) {
		return true;
	} else if(listHas(list.hashes, bytecodeSha2)) { /* Slow, if billions of hashes */
		caches.hashes.insert(bytecodeSha2); /* Caches results */
		return true;
	}
	return false;
}
}; /* namespace Susuwu */
#endif /* ndef INCLUDED_cxx_ClassResultList_cxx */

