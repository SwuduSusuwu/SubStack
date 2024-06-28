/* Dual licenses: choose "Creative Commons" or "Apache 2" (allows all uses) */
#ifndef INCLUDES_cxx_ClassObject_hxx
#define INCLUDES_cxx_ClassObject_hxx
#include <cctype> /* size_t */
#include <cassert> /* assert */
#include <iostream> /* operator+() */
#include <string> /* std::string */
#include <vector> /* std::vector */
namespace Susuwu {
typedef enum ObjectCloneAs {
	objectCloneAsShallow, /* `memcopy` */
	objectCloneAsDeep, /* Recursive `new` */
	objectCloneAsCoW, /* Copy-on-Write */
	objectCloneAsReferenceCount, /* std::shared_ptr */
	objectCloneAsNone /* (!isCloneabble()) */
} ObjectCloneAs;
typedef class Class {
public:
	virtual /* const requires C++26 */ bool operator==(const Class &obj) const = default;
	virtual const std::string getName() const { return "Susuwu::class Class"; } /* Does not return reference because https://poe.com/s/cfdFBY4gUqBaeFKLJ8uP */
} Class;
typedef class Object : Class { /* `Java` superclass based-on https://docs.oracle.com/javase%2Ftutorial%2F/java/IandI/objectclass.html https://docs.oracle.com/javase/8/docs/api/java/lang/Object.html , to assist future `Java` ports from C++ */
public:
	virtual ~Object() = default; /* release resources */
	virtual /* const -- requires C++26 */ bool operator==(const Object &obj) const = default;
	virtual const std::string getName() const { return "Susuwu::class Object"; }
	virtual const bool hasImplementation() const { return typeid(Object) != typeid(this); }
	virtual const bool isInitialized() const {return true;} /* override this if the constructor is not enough to produce usable subclass */
	virtual const bool isCloneable() const { return objectCloneAsNone != cloneableAs(); }
	virtual const bool equals(const Object &obj) const { return obj == *this; /* if you would override equals, just override operator==, as most C++ code uses operator== */ }
//	virtual const bool equals(const Object &obj) const { return operator==(obj); /* if you would override equals, just override operator==, as most C++ code uses operator== */ }
	virtual const ObjectCloneAs cloneableAs() const {
		return (usesDynamicAllocations() || usesFilesystem() || usesNetwork() || usesThreads()) ? objectCloneAsShallow : objectCloneAsNone; /* crude heuristic, override for complex classes */
	}
	virtual const bool isCloneableAs(ObjectCloneAs cloneAs) const { return cloneableAs() == cloneAs; /* must override if multiple cloneable types */ }
	virtual const Object stackClone() const {
		if(!isCloneable()) { throw std::runtime_error("Unsupported Object::clone() use"); }
		return Object(*this);
	}
	virtual Object *clone() /* TODO: `objectCloneAsReferenceCount` with const `clone` */ {
		return &(*(new Object) = stackClone());
	}
	virtual const Object stackCloneAs(ObjectCloneAs cloneAs) const {
		if(!isCloneableAs(cloneAs)) { throw std::runtime_error("Unsupported Object::cloneAs() use"); }
		return Object(*this); /* if(objectCloneAsShallow != cloneAs) { should override this } */
	}
	virtual Object *cloneAs(ObjectCloneAs cloneAs) const {
		return &(*(new Object) = stackCloneAs(cloneAs));
	}
	virtual void finalize() {
		this->~Object();
	}
	const Class &getClass() const {return *this;}
	virtual const Object *getBaseClassPtr() const { return NULL; /* no base for root class */ }
	virtual const Object &getBaseClassRef() const { return *this; /* for promises not to "return NULL", use references */ }
	virtual const size_t getStaticSize() const { return sizeof(*this); /* sizeof vtable + member variables */ }
	virtual const size_t getDynamicSize() const { return 0; /* sizeof allocations from functions such as `malloc` / `new` */ }
	virtual const bool usesDynamicAllocations() const { /* if(uses functions suchas `malloc` / `new`) {return true;} */ return false; }
	virtual const bool usesFilesystem() const { /* if(uses functions suchas `fopen` / `new`) {return true;} */ return false; }
	virtual const bool usesNetwork() const { /* if(uses functions suchas `socket`) {return true;} */ return false; }
	virtual const bool usesThreads() const { /* if(uses functions suchas `pthread`) {return true;} */ return false; }
	virtual const bool hasExtraVirtuals/*OtherThanObject*/() const { /* if(has `virtual`s other than `Object`'s) {return true;}*/ return false; }
} Object;
/* Is some slowdown to use inheritance+polymorphism with all classes;
 * https://stackoverflow.com/questions/8824587/what-is-the-purpose-of-the-final-keyword-in-c11-for-functions/78680754#78680754 shows howto use `final` to fix this */

}; /* namespace SwuduSusuwu */
#endif /* ndef INCLUDES_cxx_ClassObject_hxx */

