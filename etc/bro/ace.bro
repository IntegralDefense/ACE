##!    Derived from base/protocols/conn/contents.bro to behave similarly to vortex, minus some features
@load base/utils/files
@load base/frameworks/files/main
@load base/protocols/smtp
@load base/protocols/smtp/entities
@load base/utils/urls

module ace;

event file_new(f: fa_file) {
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
}

