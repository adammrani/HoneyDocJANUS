\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{rapportENSIAS}[2026/08/10 ENSIAS JANUS report class]
\LoadClass[a4paper,12pt]{report}

\RequirePackage[english]{babel}
\RequirePackage[utf8]{inputenc}
\RequirePackage[T1]{fontenc}
\RequirePackage[section]{placeins}
\RequirePackage{mathtools}
\RequirePackage{siunitx}
\RequirePackage{float}
\RequirePackage{graphicx}
\RequirePackage[justification=centering]{caption}
\RequirePackage{subcaption}
\RequirePackage{wallpaper}
\RequirePackage{fancyhdr}
\RequirePackage{url}
\RequirePackage[hidelinks]{hyperref}
\RequirePackage[left=2.5cm,right=2.5cm,top=2cm,bottom=3.2cm]{geometry}
\RequirePackage{titlesec}
\RequirePackage{tocloft}

\titleformat{\chapter}[display]
  {\normalfont\huge\bfseries}{\chaptertitlename\ \thechapter}{18pt}{\Huge}
\titlespacing*{\chapter}{0pt}{-10pt}{14pt}
\titleformat{\section}
  {\normalfont\Large\bfseries}{\thesection}{1em}{}

\newcommand{\ReportTitle}{Report title}
\newcommand{\ReportSubject}{Final Year Project}
\newcommand{\ReportProgram}{Cybersecurity, Cloud and Mobile Computing}
\newcommand{\ReportSupervisor}{[Supervisor name]}
\newcommand{\ReportStudents}{[Student name(s)]}
\newcommand{\ReportJury}{[Jury members]}
\newcommand{\ReportYear}{2025-2026}

\newcommand{\titre}[1]{\gdef\ReportTitle{#1}}
\newcommand{\sujet}[1]{\gdef\ReportSubject{#1}}
\newcommand{\UE}[1]{\gdef\ReportProgram{#1}}
\newcommand{\enseignant}[1]{\gdef\ReportSupervisor{#1}}
\newcommand{\eleves}[1]{\gdef\ReportStudents{#1}}
\newcommand{\jury}[1]{\gdef\ReportJury{#1}}
\newcommand{\annee}[1]{\gdef\ReportYear{#1}}

\newcommand{\fairemarges}{
  \fancyhf{}
  \fancyheadoffset{1cm}
  \setlength{\headheight}{1.5cm}
  \fancyfoot[C]{\thepage}
  \fancyfoot[L]{Final Year Project}
  \fancyfoot[R]{\ReportYear}
  \fancyhead[L]{\nouppercase{\leftmark}}
  \renewcommand{\headrulewidth}{1pt}
  \renewcommand{\footrulewidth}{1pt}
  \pagestyle{fancy}
}

\newcommand{\fairepagedegarde}{
\begin{titlepage}
  \ThisLRCornerWallPaper{1}{logos/background.png}
  \centering
  \includegraphics[width=0.29\textwidth]{logos/ensias.png}\hfill
  \includegraphics[width=0.29\textwidth]{logos/um5logo.png}\par\vspace{0.9cm}
  {\scshape\LARGE National School of Computer Science and Systems Analysis\\Rabat\par}
  \vspace{1.1cm}
  {\scshape\Large \ReportSubject\par}
  \vspace{0.45cm}
  {\large Program: \ReportProgram\par}
  \vspace{0.9cm}
  \rule{\linewidth}{0.2mm}\par\vspace{0.4cm}
  {\huge\bfseries \ReportTitle\par}
  \vspace{0.4cm}\rule{\linewidth}{0.2mm}\par
  \vspace{1.3cm}

  \begin{minipage}[t]{0.48\textwidth}
    \begin{flushleft}\large
      \textbf{Student(s):}\par
      \ReportStudents
    \end{flushleft}
  \end{minipage}
  \hfill
  \begin{minipage}[t]{0.45\textwidth}
    \begin{flushright}\large
      \textbf{Supervisor:}\par
      \ReportSupervisor
    \end{flushright}
  \end{minipage}

  \vspace{1.1cm}
  \begin{minipage}{0.7\textwidth}
    \begin{center}\large
      \textbf{Jury:}\par
      \ReportJury
    \end{center}
  \end{minipage}
  \vfill
  {\large Academic Year \ReportYear\par}
\end{titlepage}
}

\newcommand{\tabledematieres}{\tableofcontents\clearpage}
