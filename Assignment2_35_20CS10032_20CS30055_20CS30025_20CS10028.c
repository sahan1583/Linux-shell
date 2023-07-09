#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <readline/readline.h>
#include <sys/types.h>
#include <string.h>
#include <glob.h>
#include <math.h>
#include <assert.h>

#define MAX_LEN 1000

char *history[MAX_LEN];
int size = 0;
int ind = 0;

int run_cmd(char *command);

typedef void (*SigHandler)(int);

pid_t gpid;
int child_existing_status = 0;

void EstablishSignal(int sig, SigHandler handler)
{
    SigHandler res;
    res = signal(sig, handler);
    if (res == SIG_ERR)
    {
        perror("Could not establish signal handler");
        exit(EXIT_FAILURE);
    }
}

void child_sigint_handler(int sig)
{ // parent kills child. It should wait for completion of child

    EstablishSignal(SIGINT, child_sigint_handler);
    assert(sig == SIGINT);
    exit(0);
}

void parent_sigint_handler(int sig)
{ // change pid to vector of child pids

    EstablishSignal(SIGINT, parent_sigint_handler);
    assert(sig == SIGINT);
    printf("\n");
    fflush(stdout);
    if (child_existing_status == 1)
    { // kill, remove all children from running child list, in order
        kill(gpid, SIGKILL);
    }
    else
    {

        printf("$>>> ");
        fflush(stdout);
    }
}

void child_sigtstp_handler(int sig)
{
    EstablishSignal(SIGTSTP, child_sigtstp_handler);
    assert(sig == SIGTSTP);
    int status = 0;
    if (gpid == 0)
    {
        signal(SIGTSTP, SIG_DFL);
        raise(SIGTSTP);
    }
    // remove getpid() from running child list -> change in parent
}

void parent_sigtstp_handler(int sig)
{
    EstablishSignal(SIGTSTP, parent_sigtstp_handler);
    assert(sig == SIGTSTP);
    int status;
    printf("\n");
    fflush(stdout);
    if (child_existing_status == 1)
    {
        waitpid(gpid, &status, WNOHANG); // so many children, for all processes don't wait
                                         // All running child to bg. Clear running list
    }
    else
    {
        printf("$>>> ");
        fflush(stdout);
    }
}

int move_input_beginning(int count, int key)
{
    rl_beg_of_line(0, 0);
    return 0;
}
int move_input_end(int count, int key)
{
    rl_end_of_line(0, 0);
    return 0;
}

double p_time_spent(int pid)
{
    char filename[MAX_LEN];
    unsigned long utime, stime;

    sprintf(filename, "/proc/%d/stat", pid);
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Error in opening proc");
        exit(0);
    }

    // getting utime stime for pid
    fscanf(file, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu %lu", &utime, &stime);
    // fscanf(file,"%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*lu %*lu",&utime,&stime);
    fclose(file);

    // convert time from clock ticks to seconds
    clock_t clock_ticks = sysconf(_SC_CLK_TCK);
    double time_spent = (utime + stime) / (double)clock_ticks;
    printf("Time spent: %lf\n", time_spent);
    return time_spent;
}

int get_parent(int pid)
{
    int ppid;
    char fileName[1000];
    FILE *fp;
    sprintf(fileName, "/proc/%d/stat", pid);
    fp = fopen(fileName, "r");
    if (fp == NULL)
    {
        printf("Cannot open file %s\n", fileName);
        exit(1);
    }

    // reading the 4th field for parent process ID
    fscanf(fp, "%*s %*s %*s %d", &ppid);
    fclose(fp);

    return ppid;
}

int func(int pid, int flag)
{

    int ppid, status, count, child_count;
    int p_chain[1000];
    double time_spent;
    double hueristic[1000];

    
    count = 1;
    p_chain[0]=pid;
    while (count < 1000)
    {
        ppid = get_parent(pid);
        p_chain[count++] = ppid;
        printf("%d\n", ppid);
        pid = ppid;
        if (ppid == 0)
            break;
    }
    
    if (flag == 1)
    {

        FILE *fp;
        int max_index;
        long long max=0;
        char cmd[1000];
        for (int i = 0; i < count; i++)
        {
            // find time spent
            time_spent = p_time_spent(p_chain[i]);
            // find number of children

            sprintf(cmd, "ps -eo ppid|grep %d|wc -l>temp.txt", p_chain[i]);
            run_cmd(cmd);

            FILE *fp = fopen("./temp.txt", "r");
            if (fscanf(fp, "%d", &child_count) == 1)
            { // number of children
                fclose(fp);
                printf("Child count: %d\n", child_count);
            }
            // find hueristic
             hueristic[i] = pow( (time_spent+0.01), child_count*(-1) );
            //hueristic[i] = child_count - time_spent;

            // finding max
            if (max < hueristic[i])
            {
                max = hueristic[i];
                max_index = i;
            }
        }
        printf("malware detected: %d\n", p_chain[max_index]);
    }

    return 0;
}

void expand_wildcard(char *arg, char **expanded_args, int *n)
{
    glob_t results;
    int glob_result = glob(arg, GLOB_NOCHECK | GLOB_TILDE, NULL, &results);
    if (glob_result != 0)
    {
        fprintf(stderr, "Error: Failed to expand wildcard\n");
        exit(1);
    }

    for (int i = 0; i < results.gl_pathc; i++)
    {
        expanded_args[(*n)++] = strdup(results.gl_pathv[i]);
    }

    globfree(&results);
}

int up_func(int count, int key)
{
    if (ind > 0)
    {
        ind--;
        rl_replace_line(history[ind], 0);
        rl_point = rl_end;
        rl_redisplay();
    }
    return 0;
}

int down_func(int count, int key)
{
    if (ind < size - 1)
    {
        ind++;
        rl_replace_line(history[ind], 0);
        rl_point = rl_end;
        rl_redisplay();
    }
    return 0;
}

int run_cmd(char *command)
{

    int i, proc_res, in_fd = 0, o, p, ret, st, arg_count, in_file, out_file, str;
    int status;

    int lc_p[1000];
    int op_p[1000];
    int ocnt = 0;
    int lcnt = 0;
    pid_t pid;
    i = 0;
    o = 0;
    int bg = 0;
    if (command[strlen(command) - 1] == '&')
    {
        bg = 1;
        command[strlen(command) - 1] = '\0';
    }
    if (command[0] == 'c' && command[1] == 'd' && command[2] == ' ')
    {
        char tar_dir[MAX_LEN];
        strcpy(tar_dir, command + 3);
        if (tar_dir == NULL)
        {
            printf("cd: expected argument to \"cd\"\n");
        }
        else
        {
            if (strchr(tar_dir, '*') || strchr(tar_dir, '?'))
            {
                char **args = (char **)malloc(1 * sizeof(char *));
                int n = 0;
                expand_wildcard(tar_dir, args, &n);
                if (chdir(args[0]) != 0)
                {
                    perror("cd");
                }
            }
            else
            {
                if (chdir(tar_dir) != 0)
                {
                    perror("cd");
                }
            }
        }
        return 0;
    }

    gpid = fork();
    if (gpid == 0)
    {
        // signal handling for child
        EstablishSignal(SIGTSTP, child_sigtstp_handler);
        EstablishSignal(SIGINT, child_sigint_handler);

        char *pipe_cmds[MAX_LEN];
        char *cmd;

        int n_pipes = 0;
        cmd = strtok(command, "|");
        while (cmd != NULL)
        {
            pipe_cmds[n_pipes++] = cmd;
            cmd = strtok(NULL, "|");
        }
        pipe_cmds[n_pipes] = NULL;
        int pipes[2];

        for (int j = 0; j < n_pipes; j++)
        {

            if (j < n_pipes - 1)
                pipe(pipes);

            proc_res = fork();
            if (proc_res == 0)
            {

                if (j > 0)
                {
                    close(pipes[1]);
                    dup2(pipes[0], STDIN_FILENO);
                    close(pipes[0]);
                }
                if (j < n_pipes - 1)
                {
                    close(pipes[0]);
                    dup2(pipes[1], STDOUT_FILENO);
                    close(pipes[1]);
                }

                if (strcmp(pipe_cmds[j], "exit") == 0)
                {
                    return -1;
                }
                for (int k = 0; k < strlen(pipe_cmds[j]); k++)
                {
                    if (pipe_cmds[j][k] == '<')
                    {
                        char inf[MAX_LEN];
                        i = 1;
                        p = 1;
                        int x = 0;
                        while (pipe_cmds[j][k + p] == ' ')
                            p++;
                        for (int t = k + p; t < strlen(pipe_cmds[j]); t++)
                        {
                            if (pipe_cmds[j][t] == ' ' || pipe_cmds[j][t] == '>')
                            {

                                o = 1;
                                while (pipe_cmds[j][t] == ' ')
                                    t++;
                                int q = 1;
                                while (pipe_cmds[j][t + q] == ' ')
                                    q++;
                                // out_file = open(pipe_cmds[j] + t + q, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                                if (strchr(pipe_cmds[j] + t + q, '*') || strchr(pipe_cmds[j] + t + q, '?'))
                                {
                                    char **args = (char **)malloc(1 * sizeof(char *));
                                    int n = 0;
                                    expand_wildcard(pipe_cmds[j] + t + q, args, &n);
                                    out_file = open(args[0], O_WRONLY | O_CREAT | O_TRUNC, 0644);
                                }
                                else
                                {
                                    out_file = open(pipe_cmds[j] + t + q, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                                }

                                break;
                            }

                            else
                                inf[x++] = pipe_cmds[j][t];
                        }
                        inf[x] = '\0';

                        if (strchr(inf, '*') || strchr(inf, '?'))
                        {
                            char **args = (char **)malloc(1 * sizeof(char *));
                            int n = 0;
                            expand_wildcard(inf, args, &n);
                            in_file = open(args[0], O_RDONLY);
                        }
                        else
                        {
                            in_file = open(inf, O_RDONLY);
                        }

                        while (pipe_cmds[j][k - 1] == ' ')
                            k--;
                        pipe_cmds[j][k] = '\0';
                        break;
                    }
                    else if (pipe_cmds[j][k] == '>')
                    {
                        o = 1;
                        p = 1;
                        while (pipe_cmds[j][k + p] == ' ')
                            p++;
                        // out_file = open(pipe_cmds[j] + k + p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                        if (strchr(pipe_cmds[j] + k + p, '*') || strchr(pipe_cmds[j] + k + p, '?'))
                        {
                            char **args = (char **)malloc(1 * sizeof(char *));
                            int n = 0;
                            expand_wildcard(pipe_cmds[j] + k + p, args, &n);
                            out_file = open(args[0], O_WRONLY | O_CREAT | O_TRUNC, 0644);
                        }
                        else
                        {
                            out_file = open(pipe_cmds[j] + k + p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                        }
                        while (pipe_cmds[j][k - 1] == ' ')
                            k--;
                        pipe_cmds[j][k] = '\0';
                        break;
                    }
                }
                arg_count = 0;
                char *cmd_args[MAX_LEN];
                cmd_args[arg_count] = strtok(pipe_cmds[j], " ");
                while (cmd_args[arg_count] != NULL)
                {
                    arg_count++;
                    cmd_args[arg_count] = strtok(NULL, " ");
                }
                char **args = (char **)malloc(arg_count * sizeof(char *));
                args[0] = cmd_args[0];
                int n = 1;
                for (int i = 1; i < arg_count; i++)
                {
                    if (strchr(cmd_args[i], '*') || strchr(cmd_args[i], '?'))
                    {
                        expand_wildcard(cmd_args[i], args, &n);
                    }
                    else
                    {
                        args[n++] = cmd_args[i];
                    }
                }

                args[n] = NULL;
                

                if (strcmp(cmd_args[0], "sb") == 0)
                {
		     
                    int pd = atoi(cmd_args[1]);
                    int flag = 0;
                    if(arg_count==3)flag=1;
                      
                    
                    func(pd, flag);
                    exit(0);
                }
                if (strcmp(cmd_args[0], "delep") == 0)
                {

                    char dup_cmd[1000];

                    strcpy(dup_cmd, "lsof -t ");
                    strcat(dup_cmd, command + 6);
                    strcat(dup_cmd, ">open.txt");
                    run_cmd(dup_cmd);

                    strcpy(dup_cmd, "lslocks|grep ");
                    strcat(dup_cmd, command + 6);
                    strcat(dup_cmd, "|awk {print$2}>locked.txt");
                    run_cmd(dup_cmd);

                    exit(0);
                }
                if (i == 1)
                    ret = dup2(in_file, STDIN_FILENO);
                if (ret == -1)
                {
                    perror("dup2_in");
                    return 1;
                }
                if (o == 1)
                    ret = dup2(out_file, STDOUT_FILENO);
                if (ret == -1)
                {
                    perror("dup2_out");
                    return 1;
                }

                ret = execvp(args[0], args);
                if (i == 1)
                    close(in_file);
                if (o == 1)
                    close(out_file);

                if (ret == -1)
                {
                    perror("execvp");
                    return 1;
                }
                exit(0);
            }
            else
            {

                wait(&proc_res);
                close(pipes[1]);
                in_fd = pipes[0];
            }
        }

        exit(0);
    }
    else
    {
        child_existing_status = 1;
        if (bg == 0)
        {
            int wait_pid = waitpid(-1, &status, WUNTRACED);
            if (wait_pid == -1)
            {
                perror("wait");
                return 1;
            }
        }
        if (strstr(command, "delep") != NULL && strstr(command, "delep") - command == 0)
        {
            printf("The pid's of processes that has the file opened:\n");
            FILE *fp;
            fp = fopen("./open.txt", "r");

            while (fscanf(fp, "%d", &op_p[ocnt]) == 1)
            {
                printf("%d\n", op_p[ocnt]);
                ocnt++;
            }

            fclose(fp);
            printf("The pid's of processes that has the file locked:\n");
            fp = fopen("./locked.txt", "r");

            while (fscanf(fp, "%d", &lc_p[lcnt]) == 1)
            {
                printf("%d\n", lc_p[lcnt]);
                lcnt++;
            }

            fclose(fp);
            printf("Do you really want to terminate these processes and delete the file?[Y/n]");
            char rspn[2];
            scanf("%s", rspn);
            if (strcmp(rspn, "Y") == 0 || strcmp(rspn, "y") == 0)
            {
                for (int x = 0; x < ocnt; x++)
                {
                    kill(op_p[x], SIGKILL);
                }
                char delep_path[1000];
                strcpy(delep_path, command + 6);
                if (unlink(delep_path) == 0)
                    printf("Succesfully deleted file\n");
            }
        }

        else
        {
            pid = waitpid(st, &status, WNOHANG);
        }
    }

    return 0;
}

int main()
{
    rl_bind_keyseq("\\033[A", up_func);
    rl_bind_keyseq("\\033[B", down_func);
    EstablishSignal(SIGINT, parent_sigint_handler);
    EstablishSignal(SIGTSTP, parent_sigtstp_handler);
    rl_bind_keyseq("\\C-a", move_input_beginning);
    rl_bind_keyseq("\\C-e", move_input_end);

    while (1)
    {
        child_existing_status = 0;
        char *command = readline("$>>> ");

        if (*command)
        {
            history[size++] = strdup(command);
            ind = size;
        }
        if (strcmp(command, "exit") == 0)
        {
            free(command);
            break;
        }
        int res = run_cmd(command);
        if (res != 0)
            break;

        free(command);
    }

    return 0;
}
