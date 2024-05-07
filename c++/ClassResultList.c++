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
const bool resultListHashesHas(const ResultList *haystack, ResultList *caches, std::string bytes) {
 if(caches->hashes.has(Sha2(bytes))) {
  return true;
 } else if(haystack->hashes.has(Sha2(bytes))) { /* Slow, if billions of hashes */
  caches->hashes.pushback(Sha2(bytes)); /* Caches results */
  return true;
 }
 return false;
}
template<Container>
#if ALL_USES_TEXT
const size_t maxOfSizes(Container<const char *> &list) {
 auto it = std::max_element(list.begin(), list.end(), [](const auto &s, const auto &x) { return strlen(s) < strlen(x); });
 return strlen(*it); /* WARNING! `strlen()` just does UTF8-strings/hex-strings; if binary, must use `it->size()` */
}
#else
const size_t maxOfSizes(Container<const std::string> &list) {
 auto it = std::max_element(list.begin(), list.end(), [](const auto &s, const auto &x) { return s.size() < x.size(); });
 return it->size();
}
#endif /* if ALL_USES_TEXT */

template<Container>
bool haystackHas(Container<std::string> &haystack, std::string::iterator s, std::string::iterator x) {
 foreach(haystack as executable) {
  if(std::search(executable.begin(), executable.end(), s, x) {
   return true;
  }
 }
 return false;
}

template<Container>
std::tuple<std::string::iterator, std::string::iterator> smallestUniqueSubstr(std::string &needle, Container<std::string> &haystack) {
 size_t smallest = needle.length();
 auto retBegin = needle.begin(), retEnd = needle.end();
 for(auto s = retBegin; needle.end() != s; ++s) {
  for(auto x = needle.end() - 1; s != x; --x) {
   if(smallest <= x - s || haystackHas(haystack, s, x)) {
    break;
   }
   smallest = x - s;
   retBegin = s, retEnd = x;
  }
 } /* Incremental `for()` loops, is a slow method to produce unique substrings; should use binary searches, or quadratic searches, or look for the standard function which optimizes this. */
 return {retBegin, retEnd};
}
}; /* namespace Susuwu */

