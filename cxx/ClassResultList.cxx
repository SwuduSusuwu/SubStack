/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDED_cxx_ClassResultList_cxx
#define INCLUDED_cxx_ClassResultList_cxx
#include <string> /* std::string */
#include <ctype.h> /* size_t */
#include "ClassResultList.hxx" /* ResultList */
#include "ClassSha2.hxx" /* Sha2 */
namespace Susuwu {
const bool resultListHashesHas(const ResultList &list, ResultList &caches, const std::string &chars) {
	auto charsSha2 = Sha2(chars);
	if(listHas(caches.hashes, charsSha2)) {
		return true;
	} else if(listHas(list.hashes, charsSha2)) { /* Slow, if billions of hashes */
		caches.hashes.insert(charsSha2); /* Caches results */
		return true;
	}
	return false;
}
}; /* namespace Susuwu */
#endif /* ndef INCLUDED_cxx_ClassResultList_cxx */

