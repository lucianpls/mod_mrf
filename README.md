# mod_mrf

An apache module that serves tiles directly from a local MRF, 2D or 3D. 
This module takes two apache configuration directives:

 **MRF On|Off**
 
 Defaults to on if the MRF_ConfigurationFile is provided

 **MRF_ConfigurationFile  Filename**

 Points to a text file that contains lines, where the first word on a line is a directive, followed by parameters
 - Empty lines, lines that start with # are considered comments
 - Unknown directives are ignored
 - Known directives for this module are:

  **Size X Y Z C**
  - Mandatory, the size in pixels of the input MRF.  Z defaults to 1 and C defaults to 3 (usually not meaningful)

  **DataFile string**
  - Mandatory, the data file of the MRF.
  
  **PageSize X Y 1 C**
  - Optional, the pagesize in pixels.  X and Y default to 512. Z has to be 1 if C is provided, which has to match the C value from size

  **IndexFile string**
  - Optional, The index file name.
  If not provided it uses the data file name if its extension is not three letters.  
  Otherwise it uses the datafile name with the extension changed to .idx
 
  **MimeType string**
  - Optional.  Defaults to autodetect.

  **EmptyTile Size Offset FileName**
  - Optional.  By default it ignores the request if a tile is missing.
  First number is assumed to be the size, second is offset.
  If filename is not provided, it uses the data file name.

  **SkippedLevels N**
  - Optional, how many levels to ignore, at the top of the MRF pyramid.
  For example a GCS pyramid will have to skip the one tile level, so this should be 1
 
  **ETagSeed base32_string**
  - Optional, 64 bits in base32 digits.  Defaults to 0.  
  The empty tile ETag will be this value but bit 64 (65th bit) is set. All the other tiles
  have 64 bit ETags that depend on this value.
 