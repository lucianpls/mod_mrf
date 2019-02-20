# mod_mrf

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

AHTSE Control Directives for thiccs module are:

***Size X Y Z C***
 - Mandatory, at least x and y, the size in pixels of the input MRF.  Z defaults to 1 and C defaults to 3 (these are usually not meaningful)

***DataFile string start_offset size***
 - The path to the MRF data file. Can appear multiple times, with start offset and size values. Start offset and size default to zero.  Zero size means that the data size is unlimited.  At least one DataFile or Redirect directive is required.

***Redirect path start_offset size***
  - Optional, the path where the tile range request should be made. Can appear multiple times, with start offset and size values. Start offset and size default to zero.  Zero size means that the data size is unlimited.

***RetryCount N***
  - Optional, if the Redirect is also set, how many times to retry retrieving data from the redirect path.  Defaults to 4, which means it will try 5 times.  Accepts values between 0 and 99.

***PageSize X Y 1 C***
 - Optional, the pagesize in pixels.  X and Y default to 512. Z has to be 1 if C is provided, which has to match the C value from size

***IndexFile string***
 - Optional, the index file name. If not provided it uses the data file name if its extension is not three letters.  
  Otherwise it uses the first data file name with the extension changed to .idx
 
***MimeType string***
 - Optional, defaults to autodetect.

***EmptyTile Size Offset FileName***
 - Optional, provides the tile content to be sent when the requested tile is missing. By default the request is ignored, which results in a 404 error if a fallback mechanism does not exist.  if present, the first number is assumed to be the size, second is offset. If filename is not given, the first data file name is used.

***SkippedLevels N***
 - Optional, how many levels to ignore, at the top of the MRF pyramid. For example a GCS pyramid will have to skip the one tile level, so this should be 1
 
***ETagSeed base32_string***
 - Optional, 64 bits as 13 base32 digits [0-9a-v], defaults to 0. The empty tile ETag will be this value but 65th bit is set, also the only value that has this bit set. All the other tiles have 64 bit ETags that depend on this value.
 

For better performance on local files, the httpd source against which this module is compiled should include support for random file access optimization. A patch file for libapr is provided, see apr_FOPEN_RANDOM.patch

For better performance when using object stores, the mod_proxy should be patched to reuse connections on subrequests.  A patch file is included, see mod_proxy_httpd.patch
