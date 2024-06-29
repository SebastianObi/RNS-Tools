# Requirements: apt install gettext

LOCALES := az af ar az be bg bn bs ca co cs da de ee el eo en es et fa fi fr ga ha hi hr hu hy id is it ja ka ko ku lb lt lv mk mt my ne nl no pl pt ro ru si sk sl sq sr su sv th tl tr uk uz vi zh-CN zh-TW zu
LOCALES_IGNORE := de en

TRANSLATE := $(filter-out $(LOCALES_IGNORE),$(LOCALES))

locales: locales_po

locales_po:
	mkdir -p locales
	$(foreach var,$(LOCALES),mkdir -p locales/$(var)/LC_MESSAGES;)
	$(foreach var,$(LOCALES),msgmerge --update --no-fuzzy-matching --backup=off locales/$(var)/LC_MESSAGES/base.po locales/base.pot;)

translate:
	$(foreach var,$(TRANSLATE),potranslator -p locales -s en -d $(var) -t google -c -l 3 -w 50 --fuzzy_enable;)

translate_debug:
	$(foreach var,$(TRANSLATE),potranslator -p locales -s en -d $(var) -t google -c -l 9 -w 50 --fuzzy_enable;)

translate_debug_force:
	$(foreach var,$(TRANSLATE),potranslator -p locales -s en -d $(var) -t google -c -l 9 -w 50 --fuzzy_enable --msgid_force "";)

cleanlocales:
	$(foreach var,$(LOCALES),msgattrib --no-obsolete -o locales/$(var)/LC_MESSAGES/base.po locales/$(var)/LC_MESSAGES/base.po;)
