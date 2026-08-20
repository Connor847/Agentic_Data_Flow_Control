# How to run the full SWE-bench DFC pipeline — the "I've never done any of this" guide

This walks you through running **everything** in `swe_bench_dfc.ipynb` from a
completely blank slate. It assumes you have **never** used Docker, Ollama, a local
AI model, or a Jupyter notebook. Every step is spelled out. Follow it top to
bottom, in order. Do not skip.

> **How long will this take?** About **1–2 hours**, and most of that is just
> *waiting* for downloads and for the computer to churn. You do not have to watch
> it. Big downloads happen in Steps 1, 2, and 6.

> **What is this pipeline even doing?** In plain words: a small AI model reads a
> programming bug, writes a proposed fix, your notebook rewrites the shell commands
> in that fix into a standard form, and then a testing system checks the fix inside
> a safe throwaway mini-computer. You already proved the "rewriting" part works.
> This guide runs the whole thing end to end.

---

## The 5 things you will install (don't do anything yet — just read)

| # | Thing | What it is, in one sentence | Roughly how big |
|---|-------|-----------------------------|-----------------|
| 1 | **Docker Desktop** | An app that runs tiny, safe throwaway computers ("containers") so test code can't hurt your Mac. | ~1 GB app + lots of disk for test images |
| 2 | **Ollama** | A free app that runs an AI model *on your own computer* (no internet bill). | ~1 GB app |
| 3 | **The AI model** (`llama3.1:8b`) | The actual "brain" Ollama runs. | ~4.7 GB |
| 4 | **Python tools** | Small helper programs the notebook needs (`swebench`, etc.). | ~1 GB |
| 5 | **JupyterLab** | The program that opens and runs the notebook. | (part of #4) |

**Before you start, make sure you have free disk space.** Open the Apple menu ()
→ **About This Mac** → **More Info** → **Storage**. You want **at least 50 GB
free**. If you have less, delete some stuff first. The Docker test images are big.

While you're in **About This Mac**, look at the **Chip** line:
- If it says **Apple M1 / M2 / M3 / M4** → you have "Apple Silicon". (You almost
  certainly do.)
- If it says **Intel** → you have an "Intel Mac".

You'll need to know that for Step 1.

---

## A note about "Terminal"

Several steps say to "open Terminal and type a command." Terminal is an app that
comes with your Mac. To open it:

1. Press **Command () + Spacebar**. A little search box appears.
2. Type the word **Terminal** and press **Return**.
3. A window with text appears. That's it. You type a command, press **Return**, and
   wait for it to finish (it's done when you see your username and a `%` again).

**To copy a command from this guide into Terminal:** highlight it, press
**Command + C**, click the Terminal window, press **Command + V**, then press
**Return**.

---

## STEP 1 — Install Docker Desktop

Docker is what runs the safe throwaway mini-computers the tests need.

1. Open your web browser and go to: **https://www.docker.com/products/docker-desktop/**
2. Click the download button. **Pick the one that matches your chip** (from the
   "About This Mac" check above):
   - **"Download for Mac – Apple Silicon"** if you saw *Apple M1/M2/M3/M4*.
   - **"Download for Mac – Intel Chip"** if you saw *Intel*.
3. When the file finishes downloading, **double-click it** (it's named something
   like `Docker.dmg`). A window pops up.
4. In that window, **drag the Docker whale icon onto the Applications folder icon**.
   Wait for it to finish copying.
5. Open your **Applications** folder (in Finder, look in the left sidebar) and
   **double-click Docker** to start it.
6. It will ask for your **Mac password** and show some "accept the terms" screens.
   Click through them (Accept / Use recommended settings / Finish). You can skip
   any sign-in / "create an account" prompts.
7. **Wait.** Look at the very top-right of your screen (the menu bar). You'll see a
   little **whale icon** . When Docker is ready, the whale stops moving/animating.
   This can take a couple of minutes the first time.

**Give Docker enough power (one-time setting):**
1. Click the whale icon  in the top menu bar → **Settings** (gear icon).
2. Click **Resources** on the left.
3. Set **Memory** to at least **8 GB** (drag the slider). More is better if you
   have it.
4. Click **Apply & restart**.

**Check that Docker works:**
1. Open **Terminal** (Command+Space → type `Terminal` → Return).
2. Type this and press Return:
   ```
   docker run hello-world
   ```
3. If you see a paragraph that starts with **"Hello from Docker!"**, it works. 🎉
   If you see an error about "Cannot connect to the Docker daemon," Docker isn't
   finished starting — wait a minute for the whale to settle and try again.

> **Leave Docker running** (the whale stays in the menu bar) for the rest of this
> guide. If you ever restart your Mac, you must open Docker again before running
> the pipeline.

---

## STEP 2 — Install Ollama and download the AI model

Ollama runs the AI "brain" on your own machine, for free.

1. Go to: **https://ollama.com/download**
2. Click **Download for macOS**. A file downloads (like `Ollama-darwin.zip` or a
   `.dmg`).
3. If it's a `.zip`, double-click it to unzip; you'll get an **Ollama** app. Drag
   that app into your **Applications** folder. (If it's a `.dmg`, do the same
   drag-to-Applications thing as Docker.)
4. Open your **Applications** folder and **double-click Ollama** to start it. It
   may ask you to "move to Applications" or to run an install command — say yes /
   Install. When it's running you'll see a small **llama icon** in the top menu bar.
   (Ollama has no big window — it just runs quietly in the background. That's
   normal.)

**Download the model brain:**
1. Open **Terminal** (Command+Space → `Terminal` → Return).
2. Type this and press Return:
   ```
   ollama pull llama3.1:8b
   ```
3. This downloads about **4.7 GB**. You'll see a progress bar. **Wait for it to
   reach 100% and say "success."** (Go get a coffee.)

**Check that the model works:**
1. In Terminal, type:
   ```
   ollama run llama3.1:8b "say hello in five words"
   ```
2. If the AI types a short sentence back, it works. 🎉

> **Leave Ollama running** (llama icon in the menu bar) whenever you run the
> pipeline. The notebook talks to it in the background.

---

## STEP 3 — Set up the Python tools

Now we install the small helper programs the notebook needs. We'll put them in
their own tidy "workspace" so they don't tangle with anything else on your Mac.

1. Open **Terminal**.
2. Go to the folder that has your notebook. Copy-paste this exactly and press
   Return:
   ```
   cd "$DFC_ROOT"
   ```
   (Nothing visible happens — that's fine. It just means "work in this folder now.")
3. Create the tidy workspace (called a "virtual environment"). Copy-paste and Return:
   ```
   python3 -m venv dfc-env
   ```
   Wait a few seconds.
4. Turn the workspace **on**. Copy-paste and Return:
   ```
   source dfc-env/bin/activate
   ```
   You'll now see `(dfc-env)` at the start of your Terminal line. That means the
   workspace is active. **You must see `(dfc-env)` for the next commands to work.**
5. Install the helper programs. Copy-paste this whole line and Return:
   ```
   pip install swebench datasets requests unidiff pandas jupyterlab
   ```
   This downloads ~1 GB and prints a lot of text. **Wait until it stops and gives
   you your `%` prompt back.** (Ending on a line like "Successfully installed …" is
   good.)

> **If Step 5 shows red errors** (this can happen because your Mac's Python is a
> very new version, 3.14), do this instead and then repeat steps 3–5 above:
> ```
> brew install python@3.11
> ```
> then in step 3 replace `python3 -m venv dfc-env` with
> `/opt/homebrew/bin/python3.11 -m venv dfc-env`. Everything else stays the same.
> (`brew` is Homebrew, which you already have installed.)

> **IMPORTANT for later:** Every time you come back to run the pipeline in a new
> Terminal window, you must repeat steps 2 and 4 (the `cd …` and the
> `source dfc-env/bin/activate`) first, so you're back in the workspace.

---

## STEP 4 — Open the notebook

1. In the **same Terminal window** (the one showing `(dfc-env)`), copy-paste and
   Return:
   ```
   python3 -m jupyter lab
   ```
2. Your web browser opens automatically showing **JupyterLab** (a file browser on
   the left). If it doesn't open, look in the Terminal for a link starting with
   `http://localhost:8888/…`, copy it, and paste it into your browser.
3. On the left, **double-click `swe_bench_dfc.ipynb`**. The notebook opens on the
   right.

> **Leave this Terminal window alone** while JupyterLab is open — closing it closes
> JupyterLab. Open a *second* Terminal window if you need one.

---

## STEP 5 — Understand how to "run a cell" (30-second lesson)

A notebook is a stack of boxes called **cells**. Some are notes (text), some are
code. To **run** a code cell:

- Click once inside the cell (a blue/gray bar appears on its left).
- Press **Shift + Return**.
- While it's working, the cell shows `[*]` on its left. When it finishes, that
  turns into a number like `[7]`, and any output appears right below it.

**You will run the cells one at a time, top to bottom, in order.** Do not jump
ahead — later cells depend on earlier ones. If a cell shows a red error, stop and
see Troubleshooting at the bottom.

---

## STEP 6 — Run the pipeline, section by section

Scroll to the top of the notebook and run each code cell with **Shift + Return**,
in this order. Here's what each one does and what "good" looks like:

1. **§0 Configuration** — sets the options. **Leave everything as-is.** It's already
   set to `MODEL_BACKEND = "ollama"` (the free local model) and `N_INSTANCES = 5`
   (only 5 bugs, so it's quick). Good output: a line printing `Backend: ollama …`.

2. **§1 Dependencies** — loads the helper programs. Good output: nothing, or no
   error. (If the very first line `# !pip install …` is commented out with a `#`,
   that's fine — you already installed everything in Step 3.)

3. **§2 Load SWE-bench** — downloads the list of 5 bugs from the internet the first
   time. Good output: `Loaded 300 instances` and an example bug printed.

4. **§3 Canonicalization rules** — loads the rulebook. Good output:
   `56 canonicalization rules across buckets: …`.

5. **§4 Solver** — teaches the notebook how to ask the AI for a fix. Good output:
   nothing / no error.

6. **§5 Canonicalization + self-test** — this is the part you already tested. Good
   output: a rewritten diff plus a table of commands and how each was rewritten.

7. **§6 Run the pipeline** — for each of the 5 bugs, this asks your local AI
   (Ollama) to write a fix, then rewrites the commands. **This is slow** (the AI
   thinks for a while per bug). Good output: a line per bug ending in
   `injected: [...]`, then `Wrote 5 predictions`.
   - ⚠️ Ollama must be running (llama icon in the menu bar). If §6 errors about
     "connection refused," open the Ollama app and re-run the cell.

8. **§7 Apply patches (Docker harness)** — this is the **big, slow one**. It uses
   Docker to build/download a Linux test computer for each bug and run the tests.
   - ⚠️ **The first time is VERY slow** — easily **20–40+ minutes** — because it has
     to fetch/build the test images. On Apple Silicon (M-series) Macs it may be
     slower still, because the test images are built for a different chip and your
     Mac has to translate them. **This is normal. Do not panic. Just let it run.**
     The cell shows `[*]` the whole time.
   - Docker must be running (whale in the menu bar).
   - Good output: `returncode: 0` and a summary of how many "resolved."

9. **§8 Results table** — joins the test results with your rewrite records. Good
   output: a table (DataFrame) with columns like `instance_id`, `canonical`,
   `dfc_expected`, `benign`, `patch_resolved`, and a line
   `Wrote dfc_swebench_run/dfc_report.csv`.

**When §8 shows a table, you're done. 🎉** The full pipeline ran. The results file
is saved at:
`DFC/dfc_swebench_run/dfc_report.csv`

> **Don't expect the AI to actually fix many bugs.** The small local model rarely
> writes a working fix, and that's **completely fine** — this pipeline is testing
> the *command rewriting*, not the fix quality. Even "0 resolved" is a successful
> run.

---

## If you only want to re-check the command rewriting (the fast path)

You do **not** need Docker, Ollama, or any of the big installs just to confirm the
bash canonicalization works. From Terminal, in the DFC folder, with the workspace
active (`(dfc-env)` showing), that check is the §5 self-test. There's also a tiny
standalone runner for it that needs nothing but plain Python. Ask and it can be
saved permanently next to your notebook.

---

## Troubleshooting (the errors you're most likely to hit)

- **"Cannot connect to the Docker daemon" / Docker errors in §7.**
  Docker isn't running. Open the **Docker** app, wait for the whale icon to stop
  animating, then re-run the cell.

- **"Connection refused" / Ollama errors in §6.**
  Ollama isn't running. Open the **Ollama** app (llama icon should appear in the
  menu bar), then re-run the cell.

- **A cell shows `command not found` or `No module named …`.**
  Your Terminal isn't in the workspace. In the Terminal, run:
  `cd "$DFC_ROOT"` then
  `source dfc-env/bin/activate` (you should see `(dfc-env)`), then start JupyterLab
  again with `python3 -m jupyter lab`.

- **Step 3 `pip install` failed with red errors.**
  Very likely the Python-3.14 issue. Follow the "If Step 5 shows red errors" box in
  Step 3 (install Python 3.11 and rebuild the workspace).

- **My Mac ran out of disk space.**
  The Docker images are large. Free up space, or lower the number of bugs: in §0
  change `N_INSTANCES = 5` to `N_INSTANCES = 1` and re-run from §0 down.

- **§7 has been running "forever."**
  On the first run, 20–40+ minutes is normal (longer on Apple Silicon). As long as
  the cell shows `[*]` and Docker's whale is steady, it's working. Let it finish.

- **I closed my laptop / restarted.**
  Before running again: open **Docker**, open **Ollama**, then in Terminal
  `cd` into the DFC folder, `source dfc-env/bin/activate`, and
  `python3 -m jupyter lab`.

---

## The whole thing as a checklist

- [ ] 50 GB free disk, know your chip (Apple Silicon vs Intel)
- [ ] Install Docker Desktop, give it 8 GB RAM, `docker run hello-world` works
- [ ] Install Ollama, `ollama pull llama3.1:8b`, test it replies
- [ ] `cd` to DFC folder → `python3 -m venv dfc-env` → `source dfc-env/bin/activate`
- [ ] `pip install swebench datasets requests unidiff pandas jupyterlab`
- [ ] `python3 -m jupyter lab` → open `swe_bench_dfc.ipynb`
- [ ] Run cells §0 → §8 with Shift+Return, in order (Docker + Ollama running)
- [ ] See a table in §8 and `dfc_swebench_run/dfc_report.csv` → done
