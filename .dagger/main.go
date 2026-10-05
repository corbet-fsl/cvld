package main

import (
    "context"
    "strings"

    "dagger/bakeoff/internal/dagger"
)

type Bakeoff struct{}

// Check runs the step list of ci/bakeoff/commands.tsv and exports logs, per-step resource metrics and exit codes.
// With parallel=true every step runs in its own container with its own target volume; the cargo home and sccache volumes are shared.
func (m *Bakeoff) Check(
    ctx context.Context,
    source *dagger.Directory,
    image *dagger.File,
    ns string,
    levers string,
    sccacheNs string,
    runID string,
    // +default=false
    parallel bool,
) (*dagger.Directory, error) {
    tsv, err := source.File("ci/bakeoff/commands.tsv").Contents(ctx)
    if err != nil {
        return nil, err
    }
    var steps []string
    for _, line := range strings.Split(tsv, "\n") {
        if f := strings.SplitN(line, "\t", 2); len(f) == 2 && f[0] != "" {
            steps = append(steps, f[0])
        }
    }
    base := dag.Container().Import(image).
        WithDirectory("/src", source, dagger.ContainerWithDirectoryOpts{Exclude: []string{".git", ".dagger", ".crow", "dagger.json", "bakeoff-results"}}).
        WithWorkdir("/src").
        WithMountedCache("/cargo", dag.CacheVolume(ns+"-cargo")).
        WithEnvVariable("CARGO_HOME", "/cargo").
        WithEnvVariable("CARGO_TARGET_DIR", "/target").
        WithEnvVariable("BAKEOFF_LEVERS", levers).
        WithEnvVariable("BAKEOFF_RUN", runID)
    if strings.Contains(","+levers+",", ",sccache,") {
        base = base.WithMountedCache("/sccache", dag.CacheVolume(sccacheNs)).WithEnvVariable("SCCACHE_DIR", "/sccache")
    }
    script := "mkdir -p /tmp /home/build; dbus-run-session --config-file=ci/bakeoff/session.conf -- sh ci/bakeoff/run2.sh /results; du -sk /cargo /target > /results/cache-kib-$ONLY_STEP.txt; exit 0"
    out := dag.Directory()
    if !parallel {
        ctr := base.WithMountedCache("/target", dag.CacheVolume(ns+"-target")).
            WithExec([]string{"/bin/bakeoff-env", "sh", "-c", script}, dagger.ContainerWithExecOpts{Expect: dagger.ReturnTypeAny})
        return out.WithDirectory("/", ctr.Directory("/results")), nil
    }
    for _, s := range steps {
        ctr := base.WithMountedCache("/target", dag.CacheVolume(ns+"-target-"+s)).
            WithEnvVariable("ONLY_STEP", s).
            WithExec([]string{"/bin/bakeoff-env", "sh", "-c", script}, dagger.ContainerWithExecOpts{Expect: dagger.ReturnTypeAny})
        out = out.WithDirectory("/", ctr.Directory("/results"))
    }
    return out, nil
}
