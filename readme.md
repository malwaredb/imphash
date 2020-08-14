### ImpHash for Go

* The imports are sorted by the library and function name, so re-ordering the imports doesn't change the import hash. HOwever, that means the imports aren't the same as the `pefile` Python module, or other sources, such as VirusTotal.
* Fuzzy import hashes are achieved by using SSDeep to generate a fuzzy hash of the import information, after sorting.
* The same technique is applied to ELF files, since they also have imports, so why not? Don't expect the same hashes between file types.
* A similar technique is applied to Mach-O files, since they have imports as well. However, the library and imported functions aren't paired, so they're not hashed together, but instead all in one sorted list.
* Trying to run ImpHash on a static file will result in an error, that's expected since there's no data to crunch in that case.