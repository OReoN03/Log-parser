package logparser;

import query.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.File;
import java.nio.file.Path;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.io.*;

public class LogParser implements IPQuery, UserQuery, DateQuery, EventQuery, QLQuery {
    private final Path logDir;
    private final SimpleDateFormat formatter;
    private final List<String> logLines;
    private final Set<Log> logs;
    public LogParser(Path logDir) {
        this.logDir = logDir;
        this.logLines = new ArrayList<>(getLogLines());
        this.formatter = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
        this.logs  = getLogSet();
    }

    /*
    Helping methods
     */
    public Date getDate(String dateLine) {
        Date date = null;
        try {
            date = formatter.parse(dateLine);
        } catch (ParseException ignored) {}
        return date;
    }
    public boolean isDateInRange(Date logDate, Date after, Date before) {
        boolean isDateInRange = false;

        if (after != null && before != null) {
            if (after.before(logDate) && before.after(logDate)) {
                isDateInRange = true;
            }
        }
        else if (after != null) {
            if (logDate.after(after)) {
                isDateInRange = true;
            }
        }
        else if (before != null) {
            if (logDate.before(before)) {
                isDateInRange = true;
            }
        }
        else isDateInRange = true;

        return isDateInRange;
    }

    public List<String> getLogLines() {
        File directory = logDir.toFile();
        List<String> logs = new ArrayList<>();

        for (File file : directory.listFiles()) {
            if (file.getName().endsWith(".log")) {
                try {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
                    String logLine = null;
                    while ((logLine = reader.readLine()) != null) {
                        logs.add(logLine);
                    }
                    reader.close();
                } catch (IOException ignored) {}
            }
        }
        return logs;
    }

    /*
    IPQuery realisation
    */
    public int getNumberOfUniqueIPs(Date after, Date before) {
        return getUniqueIPs(after, before).size();
    }

    public Set<String> getUniqueIPs(Date after, Date before) {
        Set<String> ips = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            Date logDate = getDate(logArray[2]);

            if (isDateInRange(logDate, after, before))
                ips.add(logArray[0]);
        }
        return ips;
    }

    public Set<String> getIPsForUser(String user, Date after, Date before) {
        Set<String> ips = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String logUser = logArray[1];
            Date logDate = getDate(logArray[2]);

            if (logUser.equals(user)) {
                if (isDateInRange(logDate, after, before))
                    ips.add(logArray[0]);
            }
        }
        return ips;
    }

    public Set<String> getIPsForEvent(Event event, Date after, Date before) {
        Set<String> ips = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String logEvent = logArray[3].split(" ")[0];
            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(event.toString())) {
                if (isDateInRange(logDate, after, before))
                    ips.add(logArray[0]);
            }
        }
        return ips;
    }

    public Set<String> getIPsForStatus(Status status, Date after, Date before) {
        Set<String> ips = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String logStatus = logArray[4];
            Date logDate = getDate(logArray[2]);

            if (logStatus.equals(status.toString())) {
                if (isDateInRange(logDate, after, before))
                    ips.add(logArray[0]);
            }
        }
        return ips;
    }

    /*
    UserQuery realisation
    */

    @Override
    public Set<String> getAllUsers() {
        Set<String> users = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String logUser = logArray[1];

            users.add(logUser);
        }
        return users;
    }

    @Override
    public int getNumberOfUsers(Date after, Date before) {
        Set<String> users = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String logUser = logArray[1];
            Date logDate = getDate(logArray[2]);

            if (isDateInRange(logDate, after, before))
                users.add(logUser);
        }
        return users.size();
    }

    @Override
    public int getNumberOfUserEvents(String user, Date after, Date before) {
        Set<String> events = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String logUser = logArray[1];
            Date logDate = getDate(logArray[2]);

            if (logUser.equals(user)) {
                if (isDateInRange(logDate, after, before)) {
                    String event = logArray[3].split(" ")[0];
                    events.add(event);
                }
            }
        }
        return events.size();
    }

    @Override
    public Set<String> getUsersForIP(String ip, Date after, Date before) {
        Set<String> users = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String logIp = logArray[0];
            Date logDate = getDate(logArray[2]);

            if (logIp.equals(ip)) {
                if (isDateInRange(logDate, after, before)) {
                    String user = logArray[1];
                    users.add(user);
                }
            }
        }
        return users;
    }

    @Override
    public Set<String> getLoggedUsers(Date after, Date before) {
        Set<String> users = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String logEvent = logArray[3].split(" ")[0];
            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(Event.LOGIN.toString())) {
                if (isDateInRange(logDate, after, before)) {
                    String user = logArray[1];
                    users.add(user);
                }
            }
        }
        return users;
    }

    @Override
    public Set<String> getDownloadedPluginUsers(Date after, Date before) {
        Set<String> users = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String logEvent = logArray[3].split(" ")[0];
            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(Event.DOWNLOAD_PLUGIN.toString())) {
                if (isDateInRange(logDate, after, before)) {
                    String user = logArray[1];
                    users.add(user);
                }
            }
        }
        return users;
    }

    @Override
    public Set<String> getWroteMessageUsers(Date after, Date before) {
        Set<String> users = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String logEvent = logArray[3].split(" ")[0];
            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(Event.WRITE_MESSAGE.toString())) {
                if (isDateInRange(logDate, after, before)) {
                    String user = logArray[1];
                    users.add(user);
                }
            }
        }
        return users;
    }

    @Override
    public Set<String> getSolvedTaskUsers(Date after, Date before) {
        Set<String> users = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String logEvent = logArray[3].split(" ")[0];
            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(Event.SOLVE_TASK.toString())) {
                if (isDateInRange(logDate, after, before)) {
                    String user = logArray[1];
                    users.add(user);
                }
            }
        }
        return users;
    }

    @Override
    public Set<String> getSolvedTaskUsers(Date after, Date before, int task) {
        Set<String> users = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logEvent = logEventAndTask[0];
            int logTask = -1;
            if (logEventAndTask.length > 1)
                logTask = Integer.parseInt(logEventAndTask[1]);

            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(Event.SOLVE_TASK.toString()) && logTask == task) {
                if (isDateInRange(logDate, after, before)) {
                    String user = logArray[1];
                    users.add(user);
                }
            }
        }
        return users;
    }

    @Override
    public Set<String> getDoneTaskUsers(Date after, Date before) {
        Set<String> users = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String logEvent = logArray[3].split(" ")[0];
            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(Event.DONE_TASK.toString())) {
                if (isDateInRange(logDate, after, before)) {
                    String user = logArray[1];
                    users.add(user);
                }
            }
        }
        return users;
    }

    @Override
    public Set<String> getDoneTaskUsers(Date after, Date before, int task) {
        Set<String> users = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logEvent = logEventAndTask[0];
            int logTask = -1;
            if (logEventAndTask.length > 1)
                logTask = Integer.parseInt(logEventAndTask[1]);

            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(Event.DONE_TASK.toString()) && logTask == task) {
                if (isDateInRange(logDate, after, before)) {
                    String user = logArray[1];
                    users.add(user);
                }
            }
        }
        return users;
    }
    /*
    DateQuery realisation
     */
    @Override
    public Set<Date> getDatesForUserAndEvent(String user, Event event, Date after, Date before) {
        Set<Date> dates = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logUser = logArray[1];
            String logEvent = logEventAndTask[0];
            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(event.toString()) && logUser.equals(user)) {
                if (isDateInRange(logDate, after, before)) {
                    dates.add(logDate);
                }
            }
        }
        return dates;
    }
    @Override
    public Set<Date> getDatesWhenSomethingFailed(Date after, Date before) {
        Set<Date> dates = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");

            String logStatus = logArray[4];
            Date logDate = getDate(logArray[2]);

            if (logStatus.equals(Status.FAILED.toString())) {
                if (isDateInRange(logDate, after, before)) {
                    dates.add(logDate);
                }
            }
        }
        return dates;
    }
    @Override
    public Set<Date> getDatesWhenErrorHappened(Date after, Date before) {
        Set<Date> dates = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");

            String logStatus = logArray[4];
            Date logDate = getDate(logArray[2]);

            if (logStatus.equals(Status.ERROR.toString())) {
                if (isDateInRange(logDate, after, before)) {
                    dates.add(logDate);
                }
            }
        }
        return dates;
    }
    @Override
    public Date getDateWhenUserLoggedFirstTime(String user, Date after, Date before) {
        TreeSet<Date> dates = new TreeSet<>();
        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logUser = logArray[1];
            String logEvent = logEventAndTask[0];
            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(Event.LOGIN.toString()) && logUser.equals(user)) {
                if (isDateInRange(logDate, after, before)) {
                    dates.add(logDate);
                }
            }
        }
        return dates.pollFirst();
    }
    @Override
    public Date getDateWhenUserSolvedTask(String user, int task, Date after, Date before) {
        TreeSet<Date> dates = new TreeSet<>();
        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logEvent = logEventAndTask[0];
            int logTask = -1;
            if (logEventAndTask.length > 1)
                logTask = Integer.parseInt(logEventAndTask[1]);

            String logUser = logArray[1];
            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(Event.SOLVE_TASK.toString()) && logUser.equals(user) && logTask == task) {
                if (isDateInRange(logDate, after, before)) {
                    dates.add(logDate);
                }
            }
        }
        return dates.pollFirst();
    }
    @Override
    public Date getDateWhenUserDoneTask(String user, int task, Date after, Date before) {
        TreeSet<Date> dates = new TreeSet<>();
        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logEvent = logEventAndTask[0];
            int logTask = -1;
            if (logEventAndTask.length > 1)
                logTask = Integer.parseInt(logEventAndTask[1]);

            String logUser = logArray[1];
            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(Event.DONE_TASK.toString()) && logUser.equals(user) && logTask == task) {
                if (isDateInRange(logDate, after, before)) {
                    dates.add(logDate);
                }
            }
        }
        return dates.pollFirst();
    }
    @Override
    public Set<Date> getDatesWhenUserWroteMessage(String user, Date after, Date before) {
        Set<Date> dates = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logUser = logArray[1];
            String logEvent = logEventAndTask[0];
            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(Event.WRITE_MESSAGE.toString()) && logUser.equals(user)) {
                if (isDateInRange(logDate, after, before)) {
                    dates.add(logDate);
                }
            }
        }
        return dates;
    }
    @Override
    public Set<Date> getDatesWhenUserDownloadedPlugin(String user, Date after, Date before) {
        Set<Date> dates = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logUser = logArray[1];
            String logEvent = logEventAndTask[0];
            Date logDate = getDate(logArray[2]);

            if (logEvent.equals(Event.DOWNLOAD_PLUGIN.toString()) && logUser.equals(user)) {
                if (isDateInRange(logDate, after, before)) {
                    dates.add(logDate);
                }
            }
        }
        return dates;
    }
    /*
    EventQuery realisation
     */
    @Override
    public int getNumberOfAllEvents(Date after, Date before) {
        return getAllEvents(after, before).size();
    }
    @Override
    public Set<Event> getAllEvents(Date after, Date before) {
        Set<Event> events = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logEvent = logEventAndTask[0];
            Date logDate = getDate(logArray[2]);

            if (isDateInRange(logDate, after, before)) {
                for (Event event : Event.values()) {
                    if (event.toString().equals(logEvent))
                        events.add(event);
                }
            }
        }
        return events;
    }
    @Override
    public Set<Event> getEventsForIP(String ip, Date after, Date before) {
        Set<Event> events = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logIP = logArray[0];
            String logEvent = logEventAndTask[0];
            Date logDate = getDate(logArray[2]);

            if (logIP.equals(ip)) {
                if (isDateInRange(logDate, after, before)) {
                    for (Event event : Event.values()) {
                        if (event.toString().equals(logEvent))
                            events.add(event);
                    }
                }
            }
        }
        return events;
    }
    @Override
    public Set<Event> getEventsForUser(String user, Date after, Date before) {
        Set<Event> events = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logUser = logArray[1];
            String logEvent = logEventAndTask[0];
            Date logDate = getDate(logArray[2]);

            if (logUser.equals(user)) {
                if (isDateInRange(logDate, after, before)) {
                    for (Event event : Event.values()) {
                        if (event.toString().equals(logEvent))
                            events.add(event);
                    }
                }
            }
        }
        return events;
    }
    @Override
    public Set<Event> getFailedEvents(Date after, Date before) {
        Set<Event> events = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logEvent = logEventAndTask[0];
            String logStatus = logArray[4];
            Date logDate = getDate(logArray[2]);

            if (logStatus.equals(Status.FAILED.toString())) {
                if (isDateInRange(logDate, after, before)) {
                    for (Event event : Event.values()) {
                        if (event.toString().equals(logEvent))
                            events.add(event);
                    }
                }
            }
        }
        return events;
    }
    @Override
    public Set<Event> getErrorEvents(Date after, Date before) {
        Set<Event> events = new HashSet<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logEvent = logEventAndTask[0];
            String logStatus = logArray[4];
            Date logDate = getDate(logArray[2]);

            if (logStatus.equals(Status.ERROR.toString())) {
                if (isDateInRange(logDate, after, before)) {
                    for (Event event : Event.values()) {
                        if (event.toString().equals(logEvent))
                            events.add(event);
                    }
                }
            }
        }
        return events;
    }
    @Override
    public int getNumberOfAttemptToSolveTask(int task, Date after, Date before) {
        int numberOfAttemptToSolveTask = 0;

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logEvent = logEventAndTask[0];
            int logTask = -1;
            if (logEventAndTask.length > 1)
                logTask = Integer.parseInt(logEventAndTask[1]);
            Date logDate = getDate(logArray[2]);

            if (isDateInRange(logDate, after, before)) {
                if (logEvent.equals(Event.SOLVE_TASK.toString()) && logTask == task)
                    numberOfAttemptToSolveTask++;
            }
        }
        return numberOfAttemptToSolveTask;
    }
    @Override
    public int getNumberOfSuccessfulAttemptToSolveTask(int task, Date after, Date before) {
        int numberOfSuccessfulAttemptToSolveTask = 0;

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logEvent = logEventAndTask[0];
            int logTask = -1;
            if (logEventAndTask.length > 1)
                logTask = Integer.parseInt(logEventAndTask[1]);
            Date logDate = getDate(logArray[2]);

            if (isDateInRange(logDate, after, before)) {
                if (logEvent.equals(Event.DONE_TASK.toString())) {
                    if (logTask == task)
                        numberOfSuccessfulAttemptToSolveTask++;
                }
            }
        }
        return numberOfSuccessfulAttemptToSolveTask;
    }
    @Override
    public Map<Integer, Integer> getAllSolvedTasksAndTheirNumber(Date after, Date before) {
        HashMap<Integer, Integer> allSolvedTasksAndTheirNumber = new HashMap<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logEvent = logEventAndTask[0];
            int logTask = -1;
            if (logEventAndTask.length > 1)
                logTask = Integer.parseInt(logEventAndTask[1]);
            Date logDate = getDate(logArray[2]);

            if (isDateInRange(logDate, after, before)) {
                if (logEvent.equals(Event.SOLVE_TASK.toString())) {
                    allSolvedTasksAndTheirNumber.put(logTask, getNumberOfAttemptToSolveTask(logTask, after, before));
                }
            }
        }
        return allSolvedTasksAndTheirNumber;
    }
    @Override
    public Map<Integer, Integer> getAllDoneTasksAndTheirNumber(Date after, Date before) {
        HashMap<Integer, Integer> allDoneTasksAndTheirNumber = new HashMap<>();

        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");
            String[] logEventAndTask = logArray[3].split(" ");

            String logEvent = logEventAndTask[0];
            int logTask = -1;
            if (logEventAndTask.length > 1)
                logTask = Integer.parseInt(logEventAndTask[1]);
            Date logDate = getDate(logArray[2]);

            if (isDateInRange(logDate, after, before)) {
                if (logEvent.equals(Event.DONE_TASK.toString())) {
                    allDoneTasksAndTheirNumber.put(logTask, getNumberOfSuccessfulAttemptToSolveTask(logTask, after, before));
                }
            }
        }
        return allDoneTasksAndTheirNumber;
    }

    @Override
    public Set<Object> execute(String query) {
        Set<Object> objects = new HashSet<>();
        int objectInd = -1;

        switch (query) {
            case "get ip" : objectInd = 0;
                for (String logLine : logLines) {
                    String[] logArray = logLine.split("\t");
                    String logIP = logArray[0];
                    objects.add(logIP);
                }
                break;
            case "get user" : objectInd = 1;
                for (String logLine : logLines) {
                    String[] logArray = logLine.split("\t");
                    String logUser = logArray[1];
                    objects.add(logUser);
                }
                break;
            case "get date" : objectInd = 2;
                for (String logLine : logLines) {
                    String[] logArray = logLine.split("\t");
                    Date logDate = null;
                    try {
                        logDate = formatter.parse(logArray[2]);
                    } catch (ParseException e) {
                        throw new RuntimeException(e);
                    }
                    objects.add(logDate);
                }
                break;
            case "get event" : objectInd = 3;
                for (String logLine : logLines) {
                    String[] logArray = logLine.split("\t");
                    String[] logEventAndTask = logArray[3].split(" ");
                    String logEvent = logEventAndTask[0];
                    for (Event event : Event.values()) {
                        if (logEvent.equals(event.toString())) {
                            objects.add(event);
                        }
                    }
                }
                break;
            case "get status" : objectInd = 4;
                for (String logLine : logLines) {
                    String[] logArray = logLine.split("\t");
                    String logStatus = logArray[4];
                    for (Status status : Status.values()) {
                        if (logStatus.equals(status.toString())) {
                            objects.add(status);
                        }
                    }
                }
                break;
        }
        return objects;
    }
    public Set<Log> getLogSet() {
        Set<Log> logs = new HashSet<>();
        for (String logLine : logLines) {
            String[] logArray = logLine.split("\t");

            String logIP = logArray[0];

            String logUser = logArray[1];

            Date logDate = null;
            try {
                logDate = formatter.parse(logArray[2]);
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }

            Event event = null;
            String[] logEventAndTask = logArray[3].split(" ");
            String logEvent = logEventAndTask[0];
            int logTask = -1;
            if (logEventAndTask.length > 1)
                logTask = Integer.parseInt(logEventAndTask[1]);
            for (Event e : Event.values()) {
                if (logEvent.equals(e.toString())) {
                    event = e;
                }
            }

            Status status = null;
            String logStatus = logArray[4];
            for (Status s : Status.values()) {
                if (logStatus.equals(s.toString())) {
                    status = s;
                }
            }

            Log log = new Log(logIP, logUser, logDate, event, logTask, status);
            logs.add(log);
        }
        return logs;
    }
}
