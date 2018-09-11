##!    Derived from base/protocols/conn/contents.bro to behave similarly to vortex, minus some features
# vim: ts=4:sw=4:et
@load base/utils/files
@load base/frameworks/files/main
@load base/protocols/conn/main
@load base/protocols/smtp
@load base/protocols/smtp/entities
@load base/protocols/smtp/files
@load base/utils/urls

module brotex;

export {
    # temporary location of stream data (could be tmpfs)
    const stream_dir = "/opt/ace/var/streams" &redef;

    # storage area for final packages created for transfer to consumers (.tar files)
    # this can potentially get big if your consumers are down
    const stream_ready_dir = "/opt/ace/var/streams_ready" &redef;
}

# the list of file extensions we want to extract from HTTP
global extracted_file_extensions: set[string] = {
    "7z",
    "a3x",
    "ace",
    "au3",
    "bat",
    #"cab",
    "chm",
    "class",
    "cmd",
    "dll",
    "doc",
    "docm",
    "docx",
    "dot",
    "dotm",
    "eps",
    "exe",
    "hta",
    "jar",
    "jse",
    "lnk",
    "ocx",
    "pdf",
    "pif",
    "pps",
    "ppt",
    "pptm",
    "pptx",
    "ps",
    "ps1",
    "pub",
    "rar",
    "rtf",
    "scr",
    #"swf",
    "sys",
    "vbe",
    "vbs",
    "wsc",
    "wsf",
    "xla",
    "xls",
    "xlsm",
    "xlsx",
    "zip",
};

global mime_type_to_file_extension_map: table[string] of string = {
    ["application/excel"] = ".xls",
    ["application/x-msdos-program"] = ".exe",
    ["application/x-msexcel"] = ".xls",
    ["application/vnd.hzn-3d-crossword"] = ".x3d",
    ["video/3gpp"] = ".3gp",
    ["video/3gpp2"] = ".3g2",
    ["application/vnd.mseq"] = ".mseq",
    ["application/vnd.3m.post-it-notes"] = ".pwn",
    ["application/vnd.3gpp.pic-bw-large"] = ".plb",
    ["application/vnd.3gpp.pic-bw-small"] = ".psb",
    ["application/vnd.3gpp.pic-bw-var"] = ".pvb",
    ["application/vnd.3gpp2.tcap"] = ".tcap",
    ["application/x-7z-compressed"] = ".7z",
    ["application/x-abiword"] = ".abw",
    ["application/x-ace-compressed"] = ".ace",
    ["application/vnd.americandynamics.acc"] = ".acc",
    ["application/vnd.acucobol"] = ".acu",
    ["application/vnd.acucorp"] = ".atc",
    ["audio/adpcm"] = ".adp",
    ["application/x-authorware-bin"] = ".aab",
    ["application/x-authorware-map"] = ".aam",
    ["application/x-authorware-seg"] = ".aas",
    ["application/vnd.adobe.air-application-installer-package+zip"] = ".air",
    ["application/x-shockwave-flash"] = ".swf",
    ["application/vnd.adobe.fxp"] = ".fxp",
    ["application/pdf"] = ".pdf",
    ["application/vnd.cups-ppd"] = ".ppd",
    ["application/x-director"] = ".dir",
    ["application/vnd.adobe.xdp+xml"] = ".xdp",
    ["application/vnd.adobe.xfdf"] = ".xfdf",
    ["audio/x-aac"] = ".aac",
    ["application/vnd.ahead.space"] = ".ahead",
    ["application/vnd.airzip.filesecure.azf"] = ".azf",
    ["application/vnd.airzip.filesecure.azs"] = ".azs",
    ["application/vnd.amazon.ebook"] = ".azw",
    ["application/vnd.amiga.ami"] = ".ami",
    ["application/vnd.android.package-archive"] = ".apk",
    ["application/vnd.anser-web-certificate-issue-initiation"] = ".cii",
    ["application/vnd.anser-web-funds-transfer-initiation"] = ".fti",
    ["application/vnd.antix.game-component"] = ".atx",
    ["application/vnd.apple.installer+xml"] = ".mpkg",
    ["application/applixware"] = ".aw",
    ["application/vnd.hhe.lesson-player"] = ".les",
    ["application/vnd.aristanetworks.swi"] = ".swi",
    ["text/x-asm"] = ".s",
    ["application/atomcat+xml"] = ".atomcat",
    ["application/atomsvc+xml"] = ".atomsvc",
    ["application/atom+xml"] = ".atom, .xml",
    ["application/pkix-attr-cert"] = ".ac",
    ["audio/x-aiff"] = ".aif",
    ["video/x-msvideo"] = ".avi",
    ["application/vnd.audiograph"] = ".aep",
    ["image/vnd.dxf"] = ".dxf",
    ["model/vnd.dwf"] = ".dwf",
    ["text/plain-bas"] = ".par",
    ["application/x-bcpio"] = ".bcpio",
    ["application/octet-stream"] = ".bin",
    ["image/bmp"] = ".bmp",
    ["application/x-bittorrent"] = ".torrent",
    ["application/vnd.rim.cod"] = ".cod",
    ["application/vnd.blueice.multipass"] = ".mpm",
    ["application/vnd.bmi"] = ".bmi",
    ["application/x-sh"] = ".sh",
    ["image/prs.btif"] = ".btif",
    ["application/vnd.businessobjects"] = ".rep",
    ["application/x-bzip"] = ".bz",
    ["application/x-bzip2"] = ".bz2",
    ["application/x-csh"] = ".csh",
    ["text/x-c"] = ".c",
    ["application/vnd.chemdraw+xml"] = ".cdxml",
    ["text/css"] = ".css",
    ["chemical/x-cdx"] = ".cdx",
    ["chemical/x-cml"] = ".cml",
    ["chemical/x-csml"] = ".csml",
    ["application/vnd.contact.cmsg"] = ".cdbcmsg",
    ["application/vnd.claymore"] = ".cla",
    ["application/vnd.clonk.c4group"] = ".c4g",
    ["image/vnd.dvb.subtitle"] = ".sub",
    ["application/cdmi-capability"] = ".cdmia",
    ["application/cdmi-container"] = ".cdmic",
    ["application/cdmi-domain"] = ".cdmid",
    ["application/cdmi-object"] = ".cdmio",
    ["application/cdmi-queue"] = ".cdmiq",
    ["application/vnd.cluetrust.cartomobile-config"] = ".c11amc",
    ["application/vnd.cluetrust.cartomobile-config-pkg"] = ".c11amz",
    ["image/x-cmu-raster"] = ".ras",
    ["model/vnd.collada+xml"] = ".dae",
    ["text/csv"] = ".csv",
    ["application/mac-compactpro"] = ".cpt",
    ["application/vnd.wap.wmlc"] = ".wmlc",
    ["image/cgm"] = ".cgm",
    ["x-conference/x-cooltalk"] = ".ice",
    ["image/x-cmx"] = ".cmx",
    ["application/vnd.xara"] = ".xar",
    ["application/vnd.cosmocaller"] = ".cmc",
    ["application/x-cpio"] = ".cpio",
    ["application/vnd.crick.clicker"] = ".clkx",
    ["application/vnd.crick.clicker.keyboard"] = ".clkk",
    ["application/vnd.crick.clicker.palette"] = ".clkp",
    ["application/vnd.crick.clicker.template"] = ".clkt",
    ["application/vnd.crick.clicker.wordbank"] = ".clkw",
    ["application/vnd.criticaltools.wbs+xml"] = ".wbs",
    ["application/vnd.rig.cryptonote"] = ".cryptonote",
    ["chemical/x-cif"] = ".cif",
    ["chemical/x-cmdf"] = ".cmdf",
    ["application/cu-seeme"] = ".cu",
    ["application/prs.cww"] = ".cww",
    ["text/vnd.curl"] = ".curl",
    ["text/vnd.curl.dcurl"] = ".dcurl",
    ["text/vnd.curl.mcurl"] = ".mcurl",
    ["text/vnd.curl.scurl"] = ".scurl",
    ["application/vnd.curl.car"] = ".car",
    ["application/vnd.curl.pcurl"] = ".pcurl",
    ["application/vnd.yellowriver-custom-menu"] = ".cmp",
    ["application/dssc+der"] = ".dssc",
    ["application/dssc+xml"] = ".xdssc",
    ["application/x-debian-package"] = ".deb",
    ["audio/vnd.dece.audio"] = ".uva",
    ["image/vnd.dece.graphic"] = ".uvi",
    ["video/vnd.dece.hd"] = ".uvh",
    ["video/vnd.dece.mobile"] = ".uvm",
    ["video/vnd.uvvu.mp4"] = ".uvu",
    ["video/vnd.dece.pd"] = ".uvp",
    ["video/vnd.dece.sd"] = ".uvs",
    ["video/vnd.dece.video"] = ".uvv",
    ["application/x-dvi"] = ".dvi",
    ["application/vnd.fdsn.seed"] = ".seed",
    ["application/x-dtbook+xml"] = ".dtb",
    ["application/x-dtbresource+xml"] = ".res",
    ["application/vnd.dvb.ait"] = ".ait",
    ["application/vnd.dvb.service"] = ".svc",
    ["audio/vnd.digital-winds"] = ".eol",
    ["image/vnd.djvu"] = ".djvu",
    ["application/xml-dtd"] = ".dtd",
    ["application/vnd.dolby.mlp"] = ".mlp",
    ["application/x-doom"] = ".wad",
    ["application/vnd.dpgraph"] = ".dpg",
    ["audio/vnd.dra"] = ".dra",
    ["application/vnd.dreamfactory"] = ".dfac",
    ["audio/vnd.dts"] = ".dts",
    ["audio/vnd.dts.hd"] = ".dtshd",
    ["image/vnd.dwg"] = ".dwg",
    ["application/vnd.dynageo"] = ".geo",
    ["application/ecmascript"] = ".es",
    ["application/vnd.ecowin.chart"] = ".mag",
    ["image/vnd.fujixerox.edmics-mmr"] = ".mmr",
    ["image/vnd.fujixerox.edmics-rlc"] = ".rlc",
    ["application/exi"] = ".exi",
    ["application/vnd.proteus.magazine"] = ".mgz",
    ["application/epub+zip"] = ".epub",
    ["message/rfc822"] = ".eml",
    ["application/vnd.enliven"] = ".nml",
    ["application/vnd.is-xpr"] = ".xpr",
    ["image/vnd.xiff"] = ".xif",
    ["application/vnd.xfdl"] = ".xfdl",
    ["application/emma+xml"] = ".emma",
    ["application/vnd.ezpix-album"] = ".ez2",
    ["application/vnd.ezpix-package"] = ".ez3",
    ["image/vnd.fst"] = ".fst",
    ["video/vnd.fvt"] = ".fvt",
    ["image/vnd.fastbidsheet"] = ".fbs",
    ["application/vnd.denovo.fcselayout-link"] = ".fe_launch",
    ["video/x-f4v"] = ".f4v",
    ["video/x-flv"] = ".flv",
    ["image/vnd.fpx"] = ".fpx",
    ["image/vnd.net-fpx"] = ".npx",
    ["text/vnd.fmi.flexstor"] = ".flx",
    ["video/x-fli"] = ".fli",
    ["application/vnd.fluxtime.clip"] = ".ftc",
    ["application/vnd.fdf"] = ".fdf",
    ["text/x-fortran"] = ".f",
    ["application/vnd.mif"] = ".mif",
    ["application/vnd.framemaker"] = ".fm",
    ["image/x-freehand"] = ".fh",
    ["application/vnd.fsc.weblaunch"] = ".fsc",
    ["application/vnd.frogans.fnc"] = ".fnc",
    ["application/vnd.frogans.ltf"] = ".ltf",
    ["application/vnd.fujixerox.ddd"] = ".ddd",
    ["application/vnd.fujixerox.docuworks"] = ".xdw",
    ["application/vnd.fujixerox.docuworks.binder"] = ".xbd",
    ["application/vnd.fujitsu.oasys"] = ".oas",
    ["application/vnd.fujitsu.oasys2"] = ".oa2",
    ["application/vnd.fujitsu.oasys3"] = ".oa3",
    ["application/vnd.fujitsu.oasysgp"] = ".fg5",
    ["application/vnd.fujitsu.oasysprs"] = ".bh2",
    ["application/x-futuresplash"] = ".spl",
    ["application/vnd.fuzzysheet"] = ".fzs",
    ["image/g3fax"] = ".g3",
    ["application/vnd.gmx"] = ".gmx",
    ["model/vnd.gtw"] = ".gtw",
    ["application/vnd.genomatix.tuxedo"] = ".txd",
    ["application/vnd.geogebra.file"] = ".ggb",
    ["application/vnd.geogebra.tool"] = ".ggt",
    ["model/vnd.gdl"] = ".gdl",
    ["application/vnd.geometry-explorer"] = ".gex",
    ["application/vnd.geonext"] = ".gxt",
    ["application/vnd.geoplan"] = ".g2w",
    ["application/vnd.geospace"] = ".g3w",
    ["application/x-font-ghostscript"] = ".gsf",
    ["application/x-font-bdf"] = ".bdf",
    ["application/x-gtar"] = ".gtar",
    ["application/x-texinfo"] = ".texinfo",
    ["application/x-gnumeric"] = ".gnumeric",
    ["application/vnd.google-earth.kml+xml"] = ".kml",
    ["application/vnd.google-earth.kmz"] = ".kmz",
    ["application/vnd.grafeq"] = ".gqf",
    ["image/gif"] = ".gif",
    ["text/vnd.graphviz"] = ".gv",
    ["application/vnd.groove-account"] = ".gac",
    ["application/vnd.groove-help"] = ".ghf",
    ["application/vnd.groove-identity-message"] = ".gim",
    ["application/vnd.groove-injector"] = ".grv",
    ["application/vnd.groove-tool-message"] = ".gtm",
    ["application/vnd.groove-tool-template"] = ".tpl",
    ["application/vnd.groove-vcard"] = ".vcg",
    ["video/h261"] = ".h261",
    ["video/h263"] = ".h263",
    ["video/h264"] = ".h264",
    ["application/vnd.hp-hpid"] = ".hpid",
    ["application/vnd.hp-hps"] = ".hps",
    ["application/x-hdf"] = ".hdf",
    ["audio/vnd.rip"] = ".rip",
    ["application/vnd.hbci"] = ".hbci",
    ["application/vnd.hp-jlyt"] = ".jlt",
    ["application/vnd.hp-pcl"] = ".pcl",
    ["application/vnd.hp-hpgl"] = ".hpgl",
    ["application/vnd.yamaha.hv-script"] = ".hvs",
    ["application/vnd.yamaha.hv-dic"] = ".hvd",
    ["application/vnd.yamaha.hv-voice"] = ".hvp",
    ["application/vnd.hydrostatix.sof-data"] = ".sfd-hdstx",
    ["application/hyperstudio"] = ".stk",
    ["application/vnd.hal+xml"] = ".hal",
    ["text/html"] = ".html",
    ["application/vnd.ibm.rights-management"] = ".irm",
    ["application/vnd.ibm.secure-container"] = ".sc",
    ["text/calendar"] = ".ics",
    ["application/vnd.iccprofile"] = ".icc",
    ["image/x-icon"] = ".ico",
    ["application/vnd.igloader"] = ".igl",
    ["image/ief"] = ".ief",
    ["application/vnd.immervision-ivp"] = ".ivp",
    ["application/vnd.immervision-ivu"] = ".ivu",
    ["application/reginfo+xml"] = ".rif",
    ["text/vnd.in3d.3dml"] = ".3dml",
    ["text/vnd.in3d.spot"] = ".spot",
    ["model/iges"] = ".igs",
    ["application/vnd.intergeo"] = ".i2g",
    ["application/vnd.cinderella"] = ".cdy",
    ["application/vnd.intercon.formnet"] = ".xpw",
    ["application/vnd.isac.fcs"] = ".fcs",
    ["application/ipfix"] = ".ipfix",
    ["application/pkix-cert"] = ".cer",
    ["application/pkixcmp"] = ".pki",
    ["application/pkix-crl"] = ".crl",
    ["application/pkix-pkipath"] = ".pkipath",
    ["application/vnd.insors.igm"] = ".igm",
    ["application/vnd.ipunplugged.rcprofile"] = ".rcprofile",
    ["application/vnd.irepository.package+xml"] = ".irp",
    ["text/vnd.sun.j2me.app-descriptor"] = ".jad",
    ["application/java-archive"] = ".jar",
    ["application/java-vm"] = ".class",
    ["application/x-java-jnlp-file"] = ".jnlp",
    ["application/java-serialized-object"] = ".ser",
    ["text/x-java-source,java"] = ".java",
    ["application/javascript"] = ".js",
    ["application/json"] = ".json",
    ["application/vnd.joost.joda-archive"] = ".joda",
    ["video/jpm"] = ".jpm",
    ["image/jpeg"] = ".jpeg, .jpg",
    ["video/jpeg"] = ".jpgv",
    ["application/vnd.kahootz"] = ".ktz",
    ["application/vnd.chipnuts.karaoke-mmd"] = ".mmd",
    ["application/vnd.kde.karbon"] = ".karbon",
    ["application/vnd.kde.kchart"] = ".chrt",
    ["application/vnd.kde.kformula"] = ".kfo",
    ["application/vnd.kde.kivio"] = ".flw",
    ["application/vnd.kde.kontour"] = ".kon",
    ["application/vnd.kde.kpresenter"] = ".kpr",
    ["application/vnd.kde.kspread"] = ".ksp",
    ["application/vnd.kde.kword"] = ".kwd",
    ["application/vnd.kenameaapp"] = ".htke",
    ["application/vnd.kidspiration"] = ".kia",
    ["application/vnd.kinar"] = ".kne",
    ["application/vnd.kodak-descriptor"] = ".sse",
    ["application/vnd.las.las+xml"] = ".lasxml",
    ["application/x-latex"] = ".latex",
    ["application/vnd.llamagraphics.life-balance.desktop"] = ".lbd",
    ["application/vnd.llamagraphics.life-balance.exchange+xml"] = ".lbe",
    ["application/vnd.jam"] = ".jam",
    ["application/vnd.lotus-1-2-3"] = ".123",
    ["application/vnd.lotus-approach"] = ".apr",
    ["application/vnd.lotus-freelance"] = ".pre",
    ["application/vnd.lotus-notes"] = ".nsf",
    ["application/vnd.lotus-organizer"] = ".org",
    ["application/vnd.lotus-screencam"] = ".scm",
    ["application/vnd.lotus-wordpro"] = ".lwp",
    ["audio/vnd.lucent.voice"] = ".lvp",
    ["audio/x-mpegurl"] = ".m3u",
    ["video/x-m4v"] = ".m4v",
    ["application/mac-binhex40"] = ".hqx",
    ["application/vnd.macports.portpkg"] = ".portpkg",
    ["application/vnd.osgeo.mapguide.package"] = ".mgp",
    ["application/marc"] = ".mrc",
    ["application/marcxml+xml"] = ".mrcx",
    ["application/mxf"] = ".mxf",
    ["application/vnd.wolfram.player"] = ".nbp",
    ["application/mathematica"] = ".ma",
    ["application/mathml+xml"] = ".mathml",
    ["application/mbox"] = ".mbox",
    ["application/vnd.medcalcdata"] = ".mc1",
    ["application/mediaservercontrol+xml"] = ".mscml",
    ["application/vnd.mediastation.cdkey"] = ".cdkey",
    ["application/vnd.mfer"] = ".mwf",
    ["application/vnd.mfmp"] = ".mfm",
    ["model/mesh"] = ".msh",
    ["application/mads+xml"] = ".mads",
    ["application/mets+xml"] = ".mets",
    ["application/mods+xml"] = ".mods",
    ["application/metalink4+xml"] = ".meta4",
    ["application/vnd.ms-powerpoint.template.macroenabled.12"] = ".potm",
    ["application/vnd.ms-word.document.macroenabled.12"] = ".docm",
    ["application/vnd.ms-word.template.macroenabled.12"] = ".dotm",
    ["application/vnd.mcd"] = ".mcd",
    ["application/vnd.micrografx.flo"] = ".flo",
    ["application/vnd.micrografx.igx"] = ".igx",
    ["application/vnd.eszigno3+xml"] = ".es3",
    ["application/x-msaccess"] = ".mdb",
    ["video/x-ms-asf"] = ".asf",
    ["application/x-msdownload"] = ".exe",
    ["application/vnd.ms-artgalry"] = ".cil",
    ["application/vnd.ms-cab-compressed"] = ".cab",
    ["application/vnd.ms-ims"] = ".ims",
    ["application/x-ms-application"] = ".application",
    ["application/x-msclip"] = ".clp",
    ["image/vnd.ms-modi"] = ".mdi",
    ["application/vnd.ms-fontobject"] = ".eot",
    ["application/vnd.ms-excel"] = ".xls",
    ["application/vnd.ms-excel.addin.macroenabled.12"] = ".xlam",
    ["application/vnd.ms-excel.sheet.binary.macroenabled.12"] = ".xlsb",
    ["application/vnd.ms-excel.template.macroenabled.12"] = ".xltm",
    ["application/vnd.ms-excel.sheet.macroenabled.12"] = ".xlsm",
    ["application/vnd.ms-htmlhelp"] = ".chm",
    ["application/x-mscardfile"] = ".crd",
    ["application/vnd.ms-lrm"] = ".lrm",
    ["application/x-msmediaview"] = ".mvb",
    ["application/x-msmoney"] = ".mny",
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = ".pptx",
    ["application/vnd.openxmlformats-officedocument.presentationml.slide"] = ".sldx",
    ["application/vnd.openxmlformats-officedocument.presentationml.slideshow"] = ".ppsx",
    ["application/vnd.openxmlformats-officedocument.presentationml.template"] = ".potx",
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = ".xlsx",
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.template"] = ".xltx",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = ".docx",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.template"] = ".dotx",
    ["application/x-msbinder"] = ".obd",
    ["application/vnd.ms-officetheme"] = ".thmx",
    ["application/onenote"] = ".onetoc",
    ["audio/vnd.ms-playready.media.pya"] = ".pya",
    ["video/vnd.ms-playready.media.pyv"] = ".pyv",
    ["application/vnd.ms-powerpoint"] = ".ppt",
    ["application/vnd.ms-powerpoint.addin.macroenabled.12"] = ".ppam",
    ["application/vnd.ms-powerpoint.slide.macroenabled.12"] = ".sldm",
    ["application/vnd.ms-powerpoint.presentation.macroenabled.12"] = ".pptm",
    ["application/vnd.ms-powerpoint.slideshow.macroenabled.12"] = ".ppsm",
    ["application/vnd.ms-project"] = ".mpp",
    ["application/x-mspublisher"] = ".pub",
    ["application/x-msschedule"] = ".scd",
    ["application/x-silverlight-app"] = ".xap",
    ["application/vnd.ms-pki.stl"] = ".stl",
    ["application/vnd.ms-pki.seccat"] = ".cat",
    ["application/vnd.visio"] = ".vsd",
    ["video/x-ms-wm"] = ".wm",
    ["audio/x-ms-wma"] = ".wma",
    ["audio/x-ms-wax"] = ".wax",
    ["video/x-ms-wmx"] = ".wmx",
    ["application/x-ms-wmd"] = ".wmd",
    ["application/vnd.ms-wpl"] = ".wpl",
    ["application/x-ms-wmz"] = ".wmz",
    ["video/x-ms-wmv"] = ".wmv",
    ["video/x-ms-wvx"] = ".wvx",
    ["application/x-msmetafile"] = ".wmf",
    ["application/x-msterminal"] = ".trm",
    ["application/msword"] = ".doc",
    ["application/x-mswrite"] = ".wri",
    ["application/vnd.ms-works"] = ".wps",
    ["application/x-ms-xbap"] = ".xbap",
    ["application/vnd.ms-xpsdocument"] = ".xps",
    ["audio/midi"] = ".mid",
    ["application/vnd.ibm.minipay"] = ".mpy",
    ["application/vnd.ibm.modcap"] = ".afp",
    ["application/vnd.jcp.javame.midlet-rms"] = ".rms",
    ["application/vnd.tmobile-livetv"] = ".tmo",
    ["application/x-mobipocket-ebook"] = ".prc",
    ["application/vnd.mobius.mbk"] = ".mbk",
    ["application/vnd.mobius.dis"] = ".dis",
    ["application/vnd.mobius.plc"] = ".plc",
    ["application/vnd.mobius.mqy"] = ".mqy",
    ["application/vnd.mobius.msl"] = ".msl",
    ["application/vnd.mobius.txf"] = ".txf",
    ["application/vnd.mobius.daf"] = ".daf",
    ["text/vnd.fly"] = ".fly",
    ["application/vnd.mophun.certificate"] = ".mpc",
    ["application/vnd.mophun.application"] = ".mpn",
    ["video/mj2"] = ".mj2",
    ["audio/mpeg"] = ".mpga",
    ["video/vnd.mpegurl"] = ".mxu",
    ["video/mpeg"] = ".mpeg",
    ["application/mp21"] = ".m21",
    ["audio/mp4"] = ".mp4a",
    ["video/mp4"] = ".mp4",
    ["application/mp4"] = ".mp4",
    ["application/vnd.apple.mpegurl"] = ".m3u8",
    ["application/vnd.musician"] = ".mus",
    ["application/vnd.muvee.style"] = ".msty",
    ["application/xv+xml"] = ".mxml",
    ["application/vnd.nokia.n-gage.data"] = ".ngdat",
    ["application/vnd.nokia.n-gage.symbian.install"] = ".n-gage",
    ["application/x-dtbncx+xml"] = ".ncx",
    ["application/x-netcdf"] = ".nc",
    ["application/vnd.neurolanguage.nlu"] = ".nlu",
    ["application/vnd.dna"] = ".dna",
    ["application/vnd.noblenet-directory"] = ".nnd",
    ["application/vnd.noblenet-sealer"] = ".nns",
    ["application/vnd.noblenet-web"] = ".nnw",
    ["application/vnd.nokia.radio-preset"] = ".rpst",
    ["application/vnd.nokia.radio-presets"] = ".rpss",
    ["text/n3"] = ".n3",
    ["application/vnd.novadigm.edm"] = ".edm",
    ["application/vnd.novadigm.edx"] = ".edx",
    ["application/vnd.novadigm.ext"] = ".ext",
    ["application/vnd.flographit"] = ".gph",
    ["audio/vnd.nuera.ecelp4800"] = ".ecelp4800",
    ["audio/vnd.nuera.ecelp7470"] = ".ecelp7470",
    ["audio/vnd.nuera.ecelp9600"] = ".ecelp9600",
    ["application/oda"] = ".oda",
    ["application/ogg"] = ".ogx",
    ["audio/ogg"] = ".oga",
    ["video/ogg"] = ".ogv",
    ["application/vnd.oma.dd2+xml"] = ".dd2",
    ["application/vnd.oasis.opendocument.text-web"] = ".oth",
    ["application/oebps-package+xml"] = ".opf",
    ["application/vnd.intu.qbo"] = ".qbo",
    ["application/vnd.openofficeorg.extension"] = ".oxt",
    ["application/vnd.yamaha.openscoreformat"] = ".osf",
    ["audio/webm"] = ".weba",
    ["video/webm"] = ".webm",
    ["application/vnd.oasis.opendocument.chart"] = ".odc",
    ["application/vnd.oasis.opendocument.chart-template"] = ".otc",
    ["application/vnd.oasis.opendocument.database"] = ".odb",
    ["application/vnd.oasis.opendocument.formula"] = ".odf",
    ["application/vnd.oasis.opendocument.formula-template"] = ".odft",
    ["application/vnd.oasis.opendocument.graphics"] = ".odg",
    ["application/vnd.oasis.opendocument.graphics-template"] = ".otg",
    ["application/vnd.oasis.opendocument.image"] = ".odi",
    ["application/vnd.oasis.opendocument.image-template"] = ".oti",
    ["application/vnd.oasis.opendocument.presentation"] = ".odp",
    ["application/vnd.oasis.opendocument.presentation-template"] = ".otp",
    ["application/vnd.oasis.opendocument.spreadsheet"] = ".ods",
    ["application/vnd.oasis.opendocument.spreadsheet-template"] = ".ots",
    ["application/vnd.oasis.opendocument.text"] = ".odt",
    ["application/vnd.oasis.opendocument.text-master"] = ".odm",
    ["application/vnd.oasis.opendocument.text-template"] = ".ott",
    ["image/ktx"] = ".ktx",
    ["application/vnd.sun.xml.calc"] = ".sxc",
    ["application/vnd.sun.xml.calc.template"] = ".stc",
    ["application/vnd.sun.xml.draw"] = ".sxd",
    ["application/vnd.sun.xml.draw.template"] = ".std",
    ["application/vnd.sun.xml.impress"] = ".sxi",
    ["application/vnd.sun.xml.impress.template"] = ".sti",
    ["application/vnd.sun.xml.math"] = ".sxm",
    ["application/vnd.sun.xml.writer"] = ".sxw",
    ["application/vnd.sun.xml.writer.global"] = ".sxg",
    ["application/vnd.sun.xml.writer.template"] = ".stw",
    ["application/x-font-otf"] = ".otf",
    ["application/vnd.yamaha.openscoreformat.osfpvg+xml"] = ".osfpvg",
    ["application/vnd.osgi.dp"] = ".dp",
    ["application/vnd.palm"] = ".pdb",
    ["text/x-pascal"] = ".p",
    ["application/vnd.pawaafile"] = ".paw",
    ["application/vnd.hp-pclxl"] = ".pclxl",
    ["application/vnd.picsel"] = ".efif",
    ["image/x-pcx"] = ".pcx",
    ["image/vnd.adobe.photoshop"] = ".psd",
    ["application/pics-rules"] = ".prf",
    ["image/x-pict"] = ".pic",
    ["application/x-chat"] = ".chat",
    ["application/pkcs10"] = ".p10",
    ["application/x-pkcs12"] = ".p12",
    ["application/pkcs7-mime"] = ".p7m",
    ["application/pkcs7-signature"] = ".p7s",
    ["application/x-pkcs7-certreqresp"] = ".p7r",
    ["application/x-pkcs7-certificates"] = ".p7b",
    ["application/pkcs8"] = ".p8",
    ["application/vnd.pocketlearn"] = ".plf",
    ["image/x-portable-anymap"] = ".pnm",
    ["image/x-portable-bitmap"] = ".pbm",
    ["application/x-font-pcf"] = ".pcf",
    ["application/font-tdpfr"] = ".pfr",
    ["application/x-chess-pgn"] = ".pgn",
    ["image/x-portable-graymap"] = ".pgm",
    ["image/png"] = ".png",
    ["image/x-portable-pixmap"] = ".ppm",
    ["application/pskc+xml"] = ".pskcxml",
    ["application/vnd.ctc-posml"] = ".pml",
    ["application/postscript"] = ".ai",
    ["application/x-font-type1"] = ".pfa",
    ["application/vnd.powerbuilder6"] = ".pbd",
    ["application/pgp-signature"] = ".pgp",
    ["application/vnd.previewsystems.box"] = ".box",
    ["application/vnd.pvi.ptid1"] = ".ptid",
    ["application/pls+xml"] = ".pls",
    ["application/vnd.pg.format"] = ".str",
    ["application/vnd.pg.osasli"] = ".ei6",
    ["text/prs.lines.tag"] = ".dsc",
    ["application/x-font-linux-psf"] = ".psf",
    ["application/vnd.publishare-delta-tree"] = ".qps",
    ["application/vnd.pmi.widget"] = ".wg",
    ["application/vnd.quark.quarkxpress"] = ".qxd",
    ["application/vnd.epson.esf"] = ".esf",
    ["application/vnd.epson.msf"] = ".msf",
    ["application/vnd.epson.ssf"] = ".ssf",
    ["application/vnd.epson.quickanime"] = ".qam",
    ["application/vnd.intu.qfx"] = ".qfx",
    ["video/quicktime"] = ".qt",
    ["application/x-rar-compressed"] = ".rar",
    ["audio/x-pn-realaudio"] = ".ram",
    ["audio/x-pn-realaudio-plugin"] = ".rmp",
    ["application/rsd+xml"] = ".rsd",
    ["application/vnd.rn-realmedia"] = ".rm",
    ["application/vnd.realvnc.bed"] = ".bed",
    ["application/vnd.recordare.musicxml"] = ".mxl",
    ["application/vnd.recordare.musicxml+xml"] = ".musicxml",
    ["application/relax-ng-compact-syntax"] = ".rnc",
    ["application/vnd.data-vision.rdz"] = ".rdz",
    ["application/rdf+xml"] = ".rdf",
    ["application/vnd.cloanto.rp9"] = ".rp9",
    ["application/vnd.jisp"] = ".jisp",
    ["application/rtf"] = ".rtf",
    ["text/richtext"] = ".rtx",
    ["application/vnd.route66.link66+xml"] = ".link66",
    ["application/rss+xml"] = ".rss, .xml",
    ["application/shf+xml"] = ".shf",
    ["application/vnd.sailingtracker.track"] = ".st",
    ["image/svg+xml"] = ".svg",
    ["application/vnd.sus-calendar"] = ".sus",
    ["application/sru+xml"] = ".sru",
    ["application/set-payment-initiation"] = ".setpay",
    ["application/set-registration-initiation"] = ".setreg",
    ["application/vnd.sema"] = ".sema",
    ["application/vnd.semd"] = ".semd",
    ["application/vnd.semf"] = ".semf",
    ["application/vnd.seemail"] = ".see",
    ["application/x-font-snf"] = ".snf",
    ["application/scvp-vp-request"] = ".spq",
    ["application/scvp-vp-response"] = ".spp",
    ["application/scvp-cv-request"] = ".scq",
    ["application/scvp-cv-response"] = ".scs",
    ["application/sdp"] = ".sdp",
    ["text/x-setext"] = ".etx",
    ["video/x-sgi-movie"] = ".movie",
    ["application/vnd.shana.informed.formdata"] = ".ifm",
    ["application/vnd.shana.informed.formtemplate"] = ".itp",
    ["application/vnd.shana.informed.interchange"] = ".iif",
    ["application/vnd.shana.informed.package"] = ".ipk",
    ["application/thraud+xml"] = ".tfi",
    ["application/x-shar"] = ".shar",
    ["image/x-rgb"] = ".rgb",
    ["application/vnd.epson.salt"] = ".slt",
    ["application/vnd.accpac.simply.aso"] = ".aso",
    ["application/vnd.accpac.simply.imp"] = ".imp",
    ["application/vnd.simtech-mindmapper"] = ".twd",
    ["application/vnd.commonspace"] = ".csp",
    ["application/vnd.yamaha.smaf-audio"] = ".saf",
    ["application/vnd.smaf"] = ".mmf",
    ["application/vnd.yamaha.smaf-phrase"] = ".spf",
    ["application/vnd.smart.teacher"] = ".teacher",
    ["application/vnd.svd"] = ".svd",
    ["application/sparql-query"] = ".rq",
    ["application/sparql-results+xml"] = ".srx",
    ["application/srgs"] = ".gram",
    ["application/srgs+xml"] = ".grxml",
    ["application/ssml+xml"] = ".ssml",
    ["application/vnd.koan"] = ".skp",
    ["text/sgml"] = ".sgml",
    ["application/vnd.stardivision.calc"] = ".sdc",
    ["application/vnd.stardivision.draw"] = ".sda",
    ["application/vnd.stardivision.impress"] = ".sdd",
    ["application/vnd.stardivision.math"] = ".smf",
    ["application/vnd.stardivision.writer"] = ".sdw",
    ["application/vnd.stardivision.writer-global"] = ".sgl",
    ["application/vnd.stepmania.stepchart"] = ".sm",
    ["application/x-stuffit"] = ".sit",
    ["application/x-stuffitx"] = ".sitx",
    ["application/vnd.solent.sdkm+xml"] = ".sdkm",
    ["application/vnd.olpc-sugar"] = ".xo",
    ["audio/basic"] = ".au",
    ["application/vnd.wqd"] = ".wqd",
    ["application/vnd.symbian.install"] = ".sis",
    ["application/smil+xml"] = ".smi",
    ["application/vnd.syncml+xml"] = ".xsm",
    ["application/vnd.syncml.dm+wbxml"] = ".bdm",
    ["application/vnd.syncml.dm+xml"] = ".xdm",
    ["application/x-sv4cpio"] = ".sv4cpio",
    ["application/x-sv4crc"] = ".sv4crc",
    ["application/sbml+xml"] = ".sbml",
    ["text/tab-separated-values"] = ".tsv",
    ["image/tiff"] = ".tiff",
    ["application/vnd.tao.intent-module-archive"] = ".tao",
    ["application/x-tar"] = ".tar",
    ["application/x-tcl"] = ".tcl",
    ["application/x-tex"] = ".tex",
    ["application/x-tex-tfm"] = ".tfm",
    ["application/tei+xml"] = ".tei",
    ["text/plain"] = ".txt",
    ["application/vnd.spotfire.dxp"] = ".dxp",
    ["application/vnd.spotfire.sfs"] = ".sfs",
    ["application/timestamped-data"] = ".tsd",
    ["application/vnd.trid.tpt"] = ".tpt",
    ["application/vnd.triscape.mxs"] = ".mxs",
    ["text/troff"] = ".t",
    ["application/vnd.trueapp"] = ".tra",
    ["application/x-font-ttf"] = ".ttf",
    ["text/turtle"] = ".ttl",
    ["application/vnd.umajin"] = ".umj",
    ["application/vnd.uoml+xml"] = ".uoml",
    ["application/vnd.unity"] = ".unityweb",
    ["application/vnd.ufdl"] = ".ufd",
    ["text/uri-list"] = ".uri",
    ["application/vnd.uiq.theme"] = ".utz",
    ["application/x-ustar"] = ".ustar",
    ["text/x-uuencode"] = ".uu",
    ["text/x-vcalendar"] = ".vcs",
    ["text/x-vcard"] = ".vcf",
    ["application/x-cdlink"] = ".vcd",
    ["application/vnd.vsf"] = ".vsf",
    ["model/vrml"] = ".wrl",
    ["application/vnd.vcx"] = ".vcx",
    ["model/vnd.mts"] = ".mts",
    ["model/vnd.vtu"] = ".vtu",
    ["application/vnd.visionary"] = ".vis",
    ["video/vnd.vivo"] = ".viv",
    ["application/ccxml+xml,"] = ".ccxml",
    ["application/voicexml+xml"] = ".vxml",
    ["application/x-wais-source"] = ".src",
    ["application/vnd.wap.wbxml"] = ".wbxml",
    ["image/vnd.wap.wbmp"] = ".wbmp",
    ["audio/x-wav"] = ".wav",
    ["application/davmount+xml"] = ".davmount",
    ["application/x-font-woff"] = ".woff",
    ["application/wspolicy+xml"] = ".wspolicy",
    ["image/webp"] = ".webp",
    ["application/vnd.webturbo"] = ".wtb",
    ["application/widget"] = ".wgt",
    ["application/winhlp"] = ".hlp",
    ["text/vnd.wap.wml"] = ".wml",
    ["text/vnd.wap.wmlscript"] = ".wmls",
    ["application/vnd.wap.wmlscriptc"] = ".wmlsc",
    ["application/vnd.wordperfect"] = ".wpd",
    ["application/vnd.wt.stf"] = ".stf",
    ["application/wsdl+xml"] = ".wsdl",
    ["image/x-xbitmap"] = ".xbm",
    ["image/x-xpixmap"] = ".xpm",
    ["image/x-xwindowdump"] = ".xwd",
    ["application/x-x509-ca-cert"] = ".der",
    ["application/x-xfig"] = ".fig",
    ["application/xhtml+xml"] = ".xhtml",
    ["application/xml"] = ".xml",
    ["application/xcap-diff+xml"] = ".xdf",
    ["application/xenc+xml"] = ".xenc",
    ["application/patch-ops-error+xml"] = ".xer",
    ["application/resource-lists+xml"] = ".rl",
    ["application/rls-services+xml"] = ".rs",
    ["application/resource-lists-diff+xml"] = ".rld",
    ["application/xslt+xml"] = ".xslt",
    ["application/xop+xml"] = ".xop",
    ["application/x-xpinstall"] = ".xpi",
    ["application/xspf+xml"] = ".xspf",
    ["application/vnd.mozilla.xul+xml"] = ".xul",
    ["chemical/x-xyz"] = ".xyz",
    ["text/yaml"] = ".yaml",
    ["application/yang"] = ".yang",
    ["application/yin+xml"] = ".yin",
    ["application/vnd.zul"] = ".zir",
    ["application/zip"] = ".zip",
    ["application/vnd.handheld-entertainment+xml"] = ".zmm",
    ["application/vnd.zzazz.deck+xml"] = ".zaz",
};

redef record connection += {
    # the number of files extracted
    files_extracted: count &default=0;

    # the directory the stream data is saved to
    relative_dir: string &default="";

    # current message sub-directory
    # I guess this makes sense for both http and smtp
    message_dir: string &default="";
};

redef record HTTP::Info += {
    # the current mime_type as recorded by the event
    current_mime_type: string &default="";
};

redef record Files::Info += {
    # set to T if you find out later that you should not be analyzing the file
    blacklisted: bool &default=F;
    
    # the path this file is being extracted to
    extraction_path: string &default="";
};

redef record SMTP::Info += {
    # the list of unique URLs detected in an email message
    embedded_urls: string &default="" &log;
    # the list of file names extracted from the email message
    extracted_files: vector of string &optional &log;
};

# Define the folder you'd like files extracted into. The file names can be referenced
# against the files.log and the conn.log for the purposes of determining timestamp and
# connection-level information
redef FileExtract::prefix = fmt("%s/", brotex::stream_dir);

# this should define the is_internal and record_smtp_stream functions
# these are specific to the local network installation so are separte from this script
@load ace/brotex_local 

function record_http_stream(c: connection):bool {
    # returns T if this connection is an HTTP session we want
    print(fmt("internal orig_h %s (%s) resp_h %s", c$id$orig_h, is_internal(c$id$orig_h), is_internal(c$id$resp_h)));
    return is_internal(c$id$orig_h) && ! is_internal(c$id$resp_h);
}

function initialize_storage_directories(c:connection): bool {
    # base directory of this stream extraction
    if (! mkdir(brotex::stream_dir)) {
        syslog(fmt("unable to create directory %s", brotex::stream_dir));
        return F;
    }

    # attempt to create the base storage directory for this stream
    local relative_dir:string = c$uid;
    local temp:string = fmt("%s/%s", brotex::stream_dir, relative_dir);
    if (! mkdir(temp)) {
        syslog(fmt("unable to create directory %s", temp));
        return F;
    }
        
    # track this with the connection
    c$relative_dir = relative_dir;
    return T;
}

event http_content_type(c: connection, is_orig:bool, ty:string, subty: string) {
    c$http$current_mime_type = fmt("%s/%s", to_lower(ty), to_lower(subty));
    #print(fmt("http content type = %s/%s", ty, subty));
}

event http_message_done(c:connection, is_orig: bool, stat: http_message_stat) {
    # are we extracting from this stream?
    if (c$relative_dir == "")
        return;
    
    # write out the protocol details for http request/response
    local http_details_f = open(fmt("%s/%s/protocol.http", brotex::stream_dir, c$message_dir));
    write_file(http_details_f, fmt("ts: %s\n", c$http$ts));
    write_file(http_details_f, fmt("uid: %s\n", c$http$uid));
    write_file(http_details_f, fmt("id: %s\n", c$http$id));
    write_file(http_details_f, fmt("trans_depth: %s\n", c$http$trans_depth));
    if (c$http?$method)
        write_file(http_details_f, fmt("method: %s\n", c$http$method));
    if (c$http?$host)
        write_file(http_details_f, fmt("host: %s\n", c$http$host));
    if (c$http?$uri)
        write_file(http_details_f, fmt("uri: %s\n", c$http$uri));
    if (c$http?$referrer)
        write_file(http_details_f, fmt("referrer: %s\n", c$http$referrer));
    if (c$http?$user_agent)
        write_file(http_details_f, fmt("user_agent: %s\n", c$http$user_agent));
    if (c$http?$request_body_len)
        write_file(http_details_f, fmt("request_body_len: %s\n", c$http$request_body_len));
    if (c$http?$response_body_len)
        write_file(http_details_f, fmt("response_body_len: %s\n", c$http$response_body_len));
    if (c$http?$status_code)
        write_file(http_details_f, fmt("status_code: %s\n", c$http$status_code));
    if (c$http?$status_msg)
        write_file(http_details_f, fmt("status_msg: %s\n", c$http$status_msg));
    if (c$http?$info_code)
        write_file(http_details_f, fmt("info_code: %s\n", c$http$info_code));
    if (c$http?$info_msg)
        write_file(http_details_f, fmt("info_msg: %s\n", c$http$info_msg));
    #if (c$http?$filename)
        #write_file(http_details_f, fmt("filename: %s\n", c$http$filename));
    if (c$http?$username)
        write_file(http_details_f, fmt("username: %s\n", c$http$username));
    if (c$http?$orig_mime_types)
        write_file(http_details_f, fmt("orig_mime_types: %s\n", c$http$orig_mime_types));
    if (c$http?$resp_mime_types)
        write_file(http_details_f, fmt("resp_mime_types: %s\n", c$http$resp_mime_types));
    close(http_details_f);

    # clear out the current mime_type
    c$http$current_mime_type = "";
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) {

    if ( cmd != "." )
        return;

    # we need relative_dir past this point
    if (c$message_dir == "") {
        #syslog(fmt("stream %s is missing relative dir", c));
        return;
    }

    # we are at the end of a single message
    # go ahead and write out the protocol stuff
    local smtp_details_f = open(fmt("%s/%s/protocol.smtp", brotex::stream_dir, c$message_dir));
    write_file(smtp_details_f, fmt("ts: %s\n", c$smtp$ts));
    write_file(smtp_details_f, fmt("uid: %s\n", c$smtp$uid));
    write_file(smtp_details_f, fmt("id: %s\n", c$smtp$id));
    write_file(smtp_details_f, fmt("trans_depth: %s\n", c$smtp$trans_depth));
    if (c$smtp?$helo)
        write_file(smtp_details_f, fmt("helo: %s\n", c$smtp$helo));
    if (c$smtp?$mailfrom)
        write_file(smtp_details_f, fmt("mailfrom: %s\n", c$smtp$mailfrom));
    if (c$smtp?$rcptto)
        write_file(smtp_details_f, fmt("rcptto: %s\n", c$smtp$rcptto));
    if (c$smtp?$date)
        write_file(smtp_details_f, fmt("date: %s\n", c$smtp$date));
    if (c$smtp?$from)
        write_file(smtp_details_f, fmt("from: %s\n", c$smtp$from));
    if (c$smtp?$to)
        write_file(smtp_details_f, fmt("to: %s\n", c$smtp$to));
    if (c$smtp?$reply_to)
        write_file(smtp_details_f, fmt("reply_to: %s\n", c$smtp$reply_to));
    if (c$smtp?$msg_id)
        write_file(smtp_details_f, fmt("msg_id: %s\n", c$smtp$msg_id));
    if (c$smtp?$in_reply_to)
        write_file(smtp_details_f, fmt("in_reply_to: %s\n", c$smtp$in_reply_to));
    if (c$smtp?$subject)
        write_file(smtp_details_f, fmt("subject: %s\n", c$smtp$subject));
    if (c$smtp?$x_originating_ip)
        write_file(smtp_details_f, fmt("x_originating_ip: %s\n", c$smtp$x_originating_ip));
    if (c$smtp?$first_received)
        write_file(smtp_details_f, fmt("first_received: %s\n", c$smtp$first_received));
    if (c$smtp?$second_received)
        write_file(smtp_details_f, fmt("second_received: %s\n", c$smtp$second_received));
    if (c$smtp?$last_reply)
        write_file(smtp_details_f, fmt("last_reply: %s\n", c$smtp$last_reply));
    if (c$smtp?$path)
        write_file(smtp_details_f, fmt("path: %s\n", c$smtp$path));
    if (c$smtp?$user_agent)
        write_file(smtp_details_f, fmt("user_agent: %s\n", c$smtp$user_agent));
    close(smtp_details_f);
}

#event mime_begin_entity(c: connection) {
#}

#event mime_end_entity(c: connection) {
#}

#event smtp_data(c: connection, is_orig: bool, data: string) {
#}

#event mime_one_header(c: connection, h: mime_header_rec) {
#}

event connection_established(c: connection) &priority=-5 {
    # if this is SMTP then we want to go ahead and ...
    if (record_smtp_stream(c)) {
        # set up the recording
        initialize_storage_directories(c);

        # we want to store the entire stream as-is right here
        local stream_f:file = open(generate_extraction_filename(
            fmt("%s/%s/", brotex::stream_dir, c$relative_dir), c, ".stream"));
        set_contents_file(c$id, CONTENTS_BOTH, stream_f);

        #print(fmt("recording %s", c$uid));
    }
}

event extract_urls_to_file(f: fa_file, data: string) {
    if (! f?$conns)
        return;

    for (cid in f$conns) {
        local c: connection = f$conns[cid];

        # this needs to exist
        if (c$relative_dir == "") 
            next;

        local urls = find_all_urls(data);
        #local storage_dir = fmt("%s/%s", brotex::stream_dir, c$uid);
        #local fp = open_for_append(fmt("%s/%s/%s", brotex::stream_dir, c$relative_dir, "smtp.uriurl.crits"));
        
        for (url in urls) {
            #write_file(fp, fmt("%s\n", url));
            # we also want to send this to the log that sends it to splunk
            if (c?$smtp)
                c$smtp$embedded_urls += fmt(" %s", url);
        }

        #close(fp);
    }
}

event check_file_chunk(f: fa_file, data: string, off:count) {
    # we're only looking at the first chunk of data
    if (off != 0)
        return;

    local extract:bool = F;
    #print(fmt("checking %s", f$info$filename));

    # PE executables
    if (sub_bytes(data, 0, 2) == "MZ") {
        #print f$info$filename, " is an executable - DOIT";
        extract = T;
    }

    # JSE/VBE files
    else if (sub_bytes(data, 0, 4) == "#@~^") {
        #print f$info$filename, " is a microsoft encoded file - DOIT";
        extract = T;
    }   

    # zip-based files (zip, jar, docx, etc...)
    else if (sub_bytes(data, 0, 2) == "PK") {
        #print f$info$filename, " is a zip file - DOIT";
        extract = T;
    }

    # CLASS files
    else if (sub_bytes(data, 0, 4) == "\xCA\xFE\xBA\xBE") {
        #print f$info$filename, " is a zip file - DOIT";
        extract = T;
    }

    # office documents
    # NOTE this also include MSI files
    else if (sub_bytes(data, 0, 8) == "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        #print f$info$filename, " is a microsoft ole file - DOIT";
        extract = T;
    }   
    
    # rtf
    else if (sub_bytes(data, 0, 3) == "\\rt" || sub_bytes(data, 0, 4) == "{\\rt") {
        #print f$info$filename, " is a rtf file - DOIT";
        extract = T;
    }

    # pdf
    else if (strstr(sub_bytes(data, 0, 1024), "%PDF") != 0) {
        #print f$info$filename, "is a pdf file - DOIT";
        extract = T;
    }

    # even if none of that matches we still want to extract if the mime type or file extension is interesting
    # check mime types first TODO

    # finally check the file extension, if there is one
    else if (f$info?$filename && |f$info$filename| > 0) {
        local ext = find_last(f$info$filename, /\.[a-zA-Z0-9_]{3}$/);
        if (ext != "") {
            ext = ext[1:];
            if (ext in brotex::extracted_file_extensions) {
                #print(fmt("%s is an awesome file ext - DOIT", ext));
                extract = T;
            }
        }
    }

    if (! extract) {
        #print(fmt("not extracting %s", f$info$filename));
        Files::remove_analyzer(f, Files::ANALYZER_DATA_EVENT, [$chunk_event=check_file_chunk]);
        return;
    }

    for (cid in f$conns) {

        local c = f$conns[cid];

        # set the relative directory for this connection
        if (c$relative_dir == "")
            if (! initialize_storage_directories(c))
                return;

        # use the trans_depth to track what message we're on
        local message_dir = fmt("%s/message_%d", c$relative_dir, c$http$trans_depth);
        local temp = fmt("%s/%s", brotex::stream_dir, message_dir);
        if (! mkdir(temp)) {
            syslog(fmt("unable to create directory %s", temp));
            return;
        }

        # track this with the connection as well
        c$message_dir = message_dir;

        local fname: string;
        if (f?$info && f$info?$filename) {
            # normalize file name
            if (/[^a-zA-Z0-9_\. -]/ in f$info$filename) {
                local modified_fname: string = gsub(f$info$filename, /[^a-zA-Z0-9_\. -]/, "_");
                f$info$filename = modified_fname;
            }
            fname = fmt("%s/%s", c$message_dir, f$info$filename);
        } else
            fname = fmt("%s/%s.%s", c$message_dir, f$id, "unknown");

        f$info$extraction_path = fname;

        # does this file already exist? TODO

        #print(fmt("extracted file = %s%s", FileExtract::prefix, fname));

        # begin extracting the file
        #print(fmt("extracting file %s", f$info$filename));
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=f$info$extraction_path]);
        c$files_extracted += 1;

    }
}

function file_new_smtp(c: connection, f: fa_file):bool {
    # make sure this is an SMTP stream
    if (! record_smtp_stream(c)) 
        return F;

    # use the file name specified in the protocol if it's available
    if (c$smtp?$entity && c$smtp$entity?$filename)
        f$info$filename = c$smtp$entity$filename;

    # set the relative directory for this connection
    if (c$relative_dir == "")
        if (! initialize_storage_directories(c))
            return F;

    # use the trans_depth to track what message we're on
    local message_dir = fmt("%s/message_%d", c$relative_dir, c$smtp$trans_depth);
    local temp = fmt("%s/%s", brotex::stream_dir, message_dir);
    if (! mkdir(temp)) {
        syslog(fmt("unable to create directory %s", temp));
        return F;
    }

    # track this with the connection as well
    c$message_dir = message_dir;

    local fname: string;
    if (f?$info && f$info?$filename) {
        # if the filename contains any non-ascii characters then we replace the
        # whole thing with base64 encoded version of the file name
        if (/[^a-zA-Z0-9_\. -]/ in f$info$filename) {
            local modified_fname: string = gsub(f$info$filename, /[^a-zA-Z0-9_\. -]/, "_");
            #print(fmt("using base64 encoded %s for filename %s", modified_fname, f$info$filename));
            f$info$filename = modified_fname;
        }

        fname = fmt("%s/%s", c$message_dir, f$info$filename);

        # append this name to the list of extracted files
        # NOTE that we do NOT do this if we do not know the name of the file
        #add c$smtp$extracted_files[f$info$filename];
        f$info$filename = c$smtp$entity$filename;

        if (! c$smtp?$extracted_files)
            c$smtp$extracted_files = vector();

        c$smtp$extracted_files[|c$smtp$extracted_files|] = f$info$filename;

    } else
        fname = fmt("%s/%s.%s", c$message_dir, f$id, "unknown");

    f$info$extraction_path = fname;
    # does this file already exist? TODO

    #print(fmt("extracted file = %s%s", FileExtract::prefix, fname));

    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=f$info$extraction_path]);
    # for SMTP we want to extract any URLs in the email
    Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=extract_urls_to_file]);

    return T;
}

function file_new_http(c: connection, f: fa_file):bool {
    # check the network connection to see if we even want to look at this
    if (! record_http_stream(c))
        return F;

    # do we have a mime type according to the http protocol?
    local mime_type:string = "";

    if (c$http$current_mime_type != "") {
        #print(fmt("got mime type %s from http", c$http$current_mime_type));
        mime_type = c$http$current_mime_type;
    }

    # now figure out what to call this file
    if (! f$info?$filename) {
        if (c$http?$uri) {
            local parsed_uri = decompose_uri(c$http$uri);
            if (parsed_uri?$file_name)  {
                f$info$filename = parsed_uri$file_name;
            } else if (parsed_uri?$file_base) {
                f$info$filename = parsed_uri$file_base;
            }
        } else {
            f$info$filename = f$info$fuid;

            if (mime_type != "") {
                # otherwise use the fuid and the extension for the mime type
                if (mime_type in brotex::mime_type_to_file_extension_map) {
                    f$info$filename = fmt("%s%s", f$info$fuid, brotex::mime_type_to_file_extension_map[mime_type]);
                }
            }
        }
    } 

    # inspect the first chunk of the file to look for meta data
    # this is where we decide if we want to keep looking at the file
    Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$chunk_event=check_file_chunk]);
    return T;
}

function cleanup_stream(c: connection):bool {
    if (c$relative_dir != "") {
        #print(fmt("cleanup_stream(%s)", c$uid));
        system(fmt("rm -rf %s/%s", brotex::stream_dir, c$relative_dir));
    }

    return T;
}

event file_new(f: fa_file) {
    local cid: conn_id;
    for ( cid in f$conns ) {
        local c: connection = f$conns[cid];
        if (c?$smtp) 
            file_new_smtp(c, f);
        if (c?$http)
            file_new_http(c, f);
    }
}

event mime_all_headers(c: connection, hlist: mime_header_list) {
    # avoid streams we did not record
    if (c$relative_dir == "") {
        #print(fmt("stream %s is missing relative dir", c$uid));
        return;
    }

    # record the parsed headers in a separate file for parsing
    if (c?$smtp && c$smtp?$trans_depth) {
        local connection_parsed_f = open(fmt("%s/%s/connection.%s.parsed", brotex::stream_dir, c$relative_dir, c$smtp$trans_depth));
        write_file(connection_parsed_f, fmt("uid = %s\n", c$smtp$uid));
        write_file(connection_parsed_f, fmt("mailfrom = %s\n", c$smtp?$mailfrom ? fmt("%s", c$smtp$mailfrom) : ""));
        write_file(connection_parsed_f, fmt("rcptto = %s\n", c$smtp?$rcptto ? fmt("%s", c$smtp$rcptto) : ""));
        write_file(connection_parsed_f, fmt("from = %s\n", c$smtp?$from ? fmt("%s", c$smtp$from) : ""));
        write_file(connection_parsed_f, fmt("to = %s\n", c$smtp?$to ? fmt("%s", c$smtp$to) : ""));
        write_file(connection_parsed_f, fmt("reply_to = %s\n", c$smtp?$reply_to ? fmt("%s", c$smtp$reply_to) : ""));
        write_file(connection_parsed_f, fmt("in_reply_to = %s\n", c$smtp?$in_reply_to ? fmt("%s", c$smtp$in_reply_to) : ""));
        write_file(connection_parsed_f, fmt("msg_id = %s\n", c$smtp?$msg_id ? fmt("%s", c$smtp$msg_id) : ""));
        write_file(connection_parsed_f, fmt("subject = %s\n", c$smtp?$subject ? fmt("%s", c$smtp$subject) : ""));
        write_file(connection_parsed_f, fmt("x_originating_ip = %s\n", c$smtp?$x_originating_ip ? fmt("%s", c$smtp$x_originating_ip) : ""));
        close(connection_parsed_f);
    }
}

event connection_state_remove(c: connection) {
    #print(fmt("connection_state_remove %s", c$conn$uid));

    # avoid streams we did not record
    if (c$relative_dir == "") {
        #print(fmt("stream %s is missing relative dir", c$uid));
        return;
    }

    # this is only for the protocols we're extracting from
    if (! (c?$smtp || c?$http)) {
        #print(fmt("%s not tracked by brotex", c$conn$uid));
        cleanup_stream(c);
        return;
    }

    # only http with file extraction is dealt with
    if (c?$http && c$files_extracted == 0) {
        #print(fmt("%s has 0 files extracted", c$conn$uid));
        cleanup_stream(c);
        return;
    }
    
    # a legit smtp stream will have > 0 bytes in and > 0 bytes out
    # our firewall can kill the stream so...
    if (c?$smtp) {
        if (c$conn?$orig_bytes && c$conn$orig_bytes == 0 && c$conn?$resp_bytes && c$conn$resp_bytes == 0) {
            cleanup_stream(c);
            return;
        }
    }

    #
    # this is something I would like to improve
    # not sure how well system performs (seems to work)
    #

    # the final file extension will have .http or .smtp in the file name
    local stream_type:string;
    if (c?$http)
        stream_type = "http";
    else
        stream_type = "smtp";

    # create the tar of the stream
    local tar_path: string = fmt("%s/%s.brotex", brotex::stream_ready_dir, c$uid);
    local dest_path: string = fmt("%s/%s.%s.tar", brotex::stream_ready_dir, c$uid, stream_type);

    # archive all the files and move them off for transfer to the scanners
    system(fmt("cd %s && tar cf %s %s && mv %s %s && chmod g+w %s; rm -rf %s/%s", 
        brotex::stream_dir,         # cd
        tar_path, c$relative_dir,   # tar
        tar_path, dest_path,        # mv
        dest_path,                  # chmod
        brotex::stream_dir, c$relative_dir)); # rm
}
