# Regenerate Markdown mirrors (.md) from Org sources (.org) on demand.
# Uses headless Emacs with scripts/org-export-md.el so internal anchors
# remain deterministic across runs.
#
# Usage:
#   janet scripts/regen-docs.janet [FILE.org ...]

(defn- script-dir []
  (def cf (or (dyn :current-file) "scripts/regen-docs.janet"))
  (var idx nil)
  (for i 0 (length cf)
    (when (or (= (get cf i) (chr "/")) (= (get cf i) (chr "\\")))
      (set idx i)))
  (if idx (string/slice cf 0 idx) "."))

(defn- find-org-files [root]
  (def out @[])
  (defn scan [dir]
    (when (os/stat dir)
      (each entry (os/dir dir)
        (def full (if (= dir ".") entry (string dir "/" entry)))
        (def st (os/stat full))
        (when st
          (case (st :mode)
            :directory
            (unless (or (string/has-prefix? "." entry)
                        (= entry "jpm_tree")
                        (= entry "build"))
              (scan full))
            :file
            (when (string/has-suffix? ".org" entry)
              (array/push out full)))))))
  (scan root)
  (sort out))

(defn main [& args]
  (def targets
    (if (> (length args) 1)
      (slice args 1)
      (find-org-files ".")))
  (when (empty? targets)
    (print "No .org files found to export.")
    (os/exit 0))
  (def el-helper (string (script-dir) "/org-export-md.el"))
  (unless (os/stat el-helper)
    (eprintf "ERROR: missing Emacs export helper: %s\n" el-helper)
    (os/exit 1))
  (each f targets
    (print "Exporting " f " -> .md ...")
    (flush)
    (def rc
      (os/execute ["emacs" "--batch" "-Q" "-l" el-helper
                   f "-f" "org-md-export-to-markdown"]
                  :p))
    (unless (zero? rc)
      (eprintf "ERROR: emacs export failed for %s (exit %d)\n" f rc)
      (os/exit rc)))
  (print "Regenerated " (length targets) " markdown file(s)."))
