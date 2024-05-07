#ifndef INCLUDE_GUARD_c__ClassResultList_h__
#define INCLUDE_GUARD_c__ClassResultList_h__
#include <string>
#include <ctype>
namespace Susuwu {
typedef struct ResultList { /* Lists of files (or pages) */
 unordered_map<decltype(Sha2())> hashes; /* Unique checksums of files (or pages), to avoid duplicates, plus to do fast checks for existance */
 map<const std::string> signatures; /* Smallest substrings (or regexes, or Universal Resource Identifiers) unique to this, has uses close to `hashes` but can match if files have small differences */
 map<const std::string> bytes; /* Whole files (or pages); uses lots of space, just populate this for signature synthesis (or training CNS). */
/* Used `std::string` for binaries (versus `vector<char>`) because:
 * "If you are going to use the data in a string like fashon then you should opt for std::string as using a std::vector may confuse subsequent maintainers. If on the other hand most of the data manipulation looks like plain maths or vector like then a std::vector is more appropriate." -- https://stackoverflow.com/a/1556294/24473928
*/
} ResultList;
const bool resultListHashesHas(const ResultList *haystack, ResultList *caches, std::string bytes);
template<Container>
#if ALL_USES_TEXT
const size_t maxOfSizes(Container<const char *> &);
#else
const size_t maxOfSizes(Container<const std::string> &);
#endif /* if ALL_USES_TEXT */

template<Container>
bool haystackHas(Container<std::string> &haystack, std::string::iterator, std::string::iterator);

template<Container>
std::tuple<std::string::iterator, std::string::iterator> smallestUniqueSubstr(std::string &needle, Container<std::string> &haystack);
}; /* namespace Susuwu */
#endif /* ndef INCLUDE_GUARD_c__ClassResultList_h__ */

