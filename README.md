# mod_mrf [AHTSE](https://github.com/lucianpls/AHTSE)

An apache module that serves tiles directly from a local MRF, 2D or 3D. 
This module takes two apache configuration directives:

**MRF On|Off**
 
 Defaults to on if the MRF_ConfigurationFile is provided

**MRF_RegExp**

 Required, only requests matching this pattern are handled.  It can appear multiple times

**MRF_Indirect On|Off**

 If set, this module will only respond to internal subrequests

**MRF_ConfigurationFile  Filename**

 Points to an AHTSE Control text file, where the first word on a line is a directive, followed by parameters
 - Empty lines, lines that start with # are considered comments
 - Unknown directives are ignored

AHTSE Control Directives for this module are:

***DataFile path start_offset size***
 - The path to the MRF data file to serve tiles from. Start and size are optional, by default 
 a single DataFile is used. At least one DataFile directive is required.  If the path start 
 with colon (:) followed by slash /, the path is interpreted as an internal redirect to a path 
 within the same server, starting from DocRoot.  Otherwise it is assumed to be a local file 
 name. May appear multiple times, with different start offset and size values. If the values are 
 present, read operations within start_offset and start_offset + size are made to the data file, after the read 
 offset is adjusted downward by start_offset.
 If the read offset falls outside the range, the other DataFile entries are searched, in the order in which they 
 appear in the configuration file, but first all local files will be checked and then the redirects. This allows an MRF data file to be split into multiple parts. Single tiles 
 cannot be split, but overlapping ranges are allowed, the first match will be used. Only one read 
 operation will be issued, to the first DataFile entry that matches the range.  If the read fails, 
 the server will report an error.
 Start offset and size default to zero. Zero size means that any read above the offset will be done in 
 this data file.

***Size X Y Z C***
 - Mandatory, at least x and y, the size in pixels of the input MRF.  Z defaults to 1 and C defaults to 3 (these are usually not meaningful)

***PageSize X Y 1 C***
 - Optional, the pagesize in pixels.  X and Y default to 512. Z has to be 1 if C is provided, which has to match the C value from size

***RetryCount N***
  - Optional, [0 - 99). If the DataFiles are redirects, how many times to attempt retrieving data from 
  the source path.  Defaults to 4, which means it will try 5 times.

***IndexFile string***
 - Optional, the index file name. Can only be provided once.
  If not provided it uses the data file name if its extension is not three letters.
  Otherwise it uses the first data file name with the extension changed to .idx
  It can be a redirect path in the host namespace, if it starts with a colon :
 
***MimeType string***
 - Optional, defaults to autodetect.

***EmptyTile Size Offset FileName***
 - Optional, provides the tile content to be sent when the requested tile is missing. By default the request is ignored, which results in a 404 error if a fallback mechanism does not exist.  if present, the first number is assumed to be the size, second is offset. If filename is not given, the first data file name is used.

***SkippedLevels N***
 - Optional, how many levels to ignore, at the top of the MRF pyramid. For example a GCS pyramid will have to skip the one tile level, so this should be 1
 
***ETagSeed base32_string***
 - Optional, 64 bits as 13 base32 digits [0-9a-v], defaults to 0. The empty tile ETag will be this value but 65th bit is set, also the only value that has this bit set. All the other tiles have 64 bit ETags that depend on this value.
 
***Redirect path start_offset size***
  *Deprecated*, use the DataFile directive and start path with :

For better performance on local files, the httpd source against which this module is compiled should include support for random file access optimization. A patch file for libapr is provided, see apr_FOPEN_RANDOM.patch

For better performance when using object stores, the mod_proxy should be patched to reuse connections on subrequests.  A patch file is included, see mod_proxy_httpd.patch
