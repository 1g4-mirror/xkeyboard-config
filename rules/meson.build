# And some files that are a straight install
install_data('README', 'xkb.dtd', 'xfree98',
             install_dir: dir_xkb_rules)

base_xml = files('base.xml')
base_extras_xml = files('base.extras.xml')
dev_xml = files('dev.xml')
dev_aliases_xml = files('dev.aliases.xml')
dev_legacy_xml = files('dev.legacy.xml')

MINIMUM_PYTHON_VERSION = '3.11'
MINIMUM_PYTHON_VERSION_WITH_MODULE_FALLBACK = '3.9'
pymod = import('python')
python = pymod.find_installation('python3', modules: ['lxml'])
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
transform_xml_py = find_program('xkb-dev-to-release.py')
# FIXME
rules_from_registry_py = files(
    '__init__.py',
    'directive.py',
    'components.py',
    'group.py',
    'from_registry/__init__.py',
    'from_registry/__main__.py',
)
ruleset_stylesheet = files('xkb-dev-to-release.xslt')

foreach ruleset: ['base', 'evdev']
    # generate the "evdev" and "base" rules files

    if get_option('compat-rules')
        compat_flag = ['--compat']
    else
        compat_flag = []
    endif

    # Rules main file
    custom_target(
        'rules-@0@'.format(ruleset),
        build_by_default: true,
        command: [
            python.path(), '-m', 'rules.from_registry',
            '--xkb-config-root', meson.project_source_root(),
            '--rules', ruleset,
            '--output', '@OUTPUT@',
            dev_xml, dev_aliases_xml, dev_legacy_xml,
            base_xml, base_extras_xml,
        ] + compat_flag,
        output: ruleset,
        env: {'PYTHONPATH': meson.project_source_root()},
        depend_files: rules_from_registry_py,
        install: true,
        install_dir: dir_xkb_rules
    )

    ruleset_xml = configure_file(
        output: '@0@.xml'.format(ruleset),
        input: base_xml,
        command: [
            transform_xml_py,
            '--input', '@INPUT@',
            '--output', '@OUTPUT@',
            '--stylesheet', ruleset_stylesheet
        ],
        install: true,
        install_dir: dir_xkb_rules
    )

    # This is used by the man page's meson.build
    if ruleset == 'evdev'
      evdev_ruleset = ruleset_xml
    endif

    # Rules extra file
    ruleset_extra_xml = configure_file(
        output: '@0@.extras.xml'.format(ruleset),
        input: base_extras_xml,
        command: [
            transform_xml_py,
            '--input', '@INPUT@',
            '--output', '@OUTPUT@',
            '--stylesheet', ruleset_stylesheet
        ],
        install: true,
        install_dir: dir_xkb_rules
    )

    # Generate the evdev.lst and base.lst legacy registry files
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

