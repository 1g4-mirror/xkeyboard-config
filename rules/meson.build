# And some files that are a straight install
install_data('README', 'xkb.dtd', 'xfree98',
             install_dir: dir_xkb_rules)

base_xml = files('base.xml')
base_extras_xml = files('base.extras.xml')

MINIMUM_PYTHON_VERSION = '3.11'
MINIMUM_PYTHON_VERSION_WITH_MODULE_FALLBACK = '3.9'
pymod = import('python')
python = pymod.find_installation('python3')
if python.language_version().version_compare('<@0@'.format(MINIMUM_PYTHON_VERSION))
    # Now require strenum module as fallback
    python = pymod.find_installation('python3', modules: ['strenum'])
    if python.language_version().version_compare('<@0@'.format(MINIMUM_PYTHON_VERSION_WITH_MODULE_FALLBACK))
        error('Minimum required Python version: @0@, but got: @1@'.format(
            MINIMUM_PYTHON_VERSION_WITH_MODULE_FALLBACK,
            python.language_version()
        ))
    endif
endif
xml2lst = find_program('xml2lst.pl')
foreach ruleset: ['base', 'evdev']
    # generate the "evdev" and "base" rules files



    # This is used by the man page's meson.build
    if ruleset == 'evdev'
      evdev_ruleset = ruleset_xml
    endif


    lst_file = '@0@.lst'.format(ruleset)
    custom_target(lst_file,
                  build_by_default: true,
                  command: [xml2lst, ruleset_xml],
                  capture: true,
                  output: lst_file,
                  install: true,
                  install_dir: dir_xkb_rules)

endforeach

if get_option('xorg-rules-symlinks')
  foreach suffix: ['', '.lst', '.xml']
    if meson.version().version_compare('>= 0.61')
      install_symlink('xorg' + suffix,
                      pointing_to: 'base' + suffix,
                      install_dir: dir_xkb_rules)
    else
      meson.add_install_script('sh', '-c',
        'ln -s base@0@ $DESTDIR@1@/xorg@0@'.format(suffix, dir_xkb_rules))
    endif
  endforeach
endif
# Copy the DTD to the build directory, the man page generation expects it in
# the same directory as the input XML file.
configure_file(output: 'xkb.dtd',
               input: 'xkb.dtd',
               copy: true,
               install: false)
