/* Licenses: allows all uses ("Creative Commons"/"Apache 2") */
#ifndef INCLUDE_GUARD_c__ClassResultList_h__
#define INCLUDE_GUARD_c__ClassResultList_h__
#include <iostream> /* std::string */
#include <set> /* std::set */
#include <unordered_set> /* std::unordered_set */
#include <ctype.h>
namespace Susuwu {
typedef struct ResultList { /* Lists of files (or pages) */
	std::unordered_set<decltype(Sha2())> hashes; /* Unique checksums of files (or pages), to avoid duplicates, plus to do fast checks for existance */
	std::set<const std::string> signatures; /* Smallest substrings (or regexes, or Universal Resource Identifiers) unique to this, has uses close to `hashes` but can match if files have small differences */
	std::set<const std::string> bytes; /* Whole files (or pages); uses lots of space, just populate this for signature synthesis (or training CNS). */
/* Used `std::string` for binaries (versus `vector<char>`) because:
 * "If you are going to use the data in a string like fashon then you should opt for std::string as using a std::vector may confuse subsequent maintainers. If on the other hand most of the data manipulation looks like plain maths or vector like then a std::vector is more appropriate." -- https://stackoverflow.com/a/1556294/24473928
*/
} ResultList;
const bool resultListHashesHas(const ResultList *haystack, ResultList *caches, std::string bytes);
template<class Container>
#if ALL_USES_TEXT
const size_t maxOfSizes(Container<const char *> &);
#else
const size_t maxOfSizes(Container<const std::string> &);
#endif /* if ALL_USES_TEXT */

template<class Container>
const bool haystackHas(const Container &haystack, std::string::const_iterator, std::string::const_iterator);

template<class Container>
const std::tuple<std::string::const_iterator, std::string::const_iterator> smallestUniqueSubstr(const std::string &needle, const Container &haystack);
}; /* namespace Susuwu */
#endif /* ndef INCLUDE_GUARD_c__ClassResultList_h__ */

