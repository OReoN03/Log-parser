package logparser;

import query.*;

import java.io.*;
import java.nio.file.Path;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class EnhancedLogParser implements IPQuery, UserQuery, DateQuery, EventQuery, QLQuery {
    private final Path logDir;
    private final SimpleDateFormat formatter;
    private final List<String> logLines;
    private final Set<Log> logs;

    public EnhancedLogParser(Path logDir) {
        this.logDir = logDir;
        this.logLines = new ArrayList<>(getLogLines());
        this.formatter = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
        this.logs = getLogSet();
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

    @Override
    public Set<Object> execute(String query) {
        Set<Object> result = new HashSet<>();
        String field1;
        String field2 = null;
        String value1 = null;
        Date after = null;
        Date before = null;

        Pattern pattern = Pattern.compile("get (ip|user|date|event|status)" +
                "( for (ip|user|date|event|status) = \"(.*?)\")?" +
                "( and date between \"(.*?)\"" + " and \"(.*?)\")?");
        Matcher matcher = pattern.matcher(query);
        matcher.find();
        field1 = matcher.group(1);
        if (matcher.group(2) != null) {
            field2 = matcher.group(3);
            value1 = matcher.group(4);
            if (matcher.group(5) != null) {
                try {
                    after = formatter.parse(matcher.group(6));
                    before = formatter.parse(matcher.group(7));
                } catch (ParseException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        if (field2 != null && value1 != null) {
            for (Log log : logs) {
                if (isDateInRange(log.getLogDate(), after, before)) {
                    if (field2.equals("date")) {
                        try {
                            if (log.getLogDate().getTime() == formatter.parse(value1).getTime()) {
                                result.add(getCurrentValue(log, field1));
                            }
                        } catch (ParseException ignored) {
                        }
                    } else if (value1.equals(getCurrentValue(log, field2).toString())) {
                        result.add(getCurrentValue(log, field1));
                    }
                }
            }
        }
        else {
            for (Log log : logs) {
                result.add(getCurrentValue(log, field1));
            }
        }
        return result;
    }

    public Object getCurrentValue(Log log, String field) {
        Object value = null;
        switch (field) {
            case "ip":
                value = log.getIp();
                break;
            case "user":
                value = log.getUser();
                break;
            case "date":
                value = log.getLogDate();
                break;
            case "event":
                value = log.getEvent();
                break;
            case "status":
                value = log.getStatus();
                break;
        }
        return value;
    }

    @Override
    public Set<Date> getDatesForUserAndEvent(String user, Event event, Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getUser().equals(user)).
                filter(x -> x.getEvent().equals(event)).
                map(Log::getLogDate).collect(Collectors.toSet());
    }

    @Override
    public Set<Date> getDatesWhenSomethingFailed(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getStatus().equals(Status.FAILED)).
                map(Log::getLogDate).collect(Collectors.toSet());
    }

    @Override
    public Set<Date> getDatesWhenErrorHappened(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getStatus().equals(Status.ERROR)).
                map(Log::getLogDate).collect(Collectors.toSet());
    }

    @Override
    public Date getDateWhenUserLoggedFirstTime(String user, Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getUser().equals(user)).
                filter(x -> x.getEvent().equals(Event.LOGIN)).
                filter(x -> x.getStatus().equals(Status.OK)).
                map(Log::getLogDate).min(Date::compareTo).orElse(null);
    }

    @Override
    public Date getDateWhenUserSolvedTask(String user, int task, Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getUser().equals(user)).
                filter(x -> x.getEvent().equals(Event.SOLVE_TASK)).
                filter(x -> x.getTask() == task).
                map(Log::getLogDate).min(Date::compareTo).orElse(null);
    }

    @Override
    public Date getDateWhenUserDoneTask(String user, int task, Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getUser().equals(user)).
                filter(x -> x.getEvent().equals(Event.DONE_TASK)).
                filter(x -> x.getTask() == task).
                map(Log::getLogDate).min(Date::compareTo).orElse(null);
    }

    @Override
    public Set<Date> getDatesWhenUserWroteMessage(String user, Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getUser().equals(user)).
                filter(x -> x.getEvent().equals(Event.WRITE_MESSAGE)).
                map(Log::getLogDate).collect(Collectors.toSet());
    }

    @Override
    public Set<Date> getDatesWhenUserDownloadedPlugin(String user, Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getUser().equals(user)).
                filter(x -> x.getEvent().equals(Event.DOWNLOAD_PLUGIN)).
                map(Log::getLogDate).collect(Collectors.toSet());
    }

    @Override
    public int getNumberOfAllEvents(Date after, Date before) {
        return getAllEvents(after, before).size();
    }

    @Override
    public Set<Event> getAllEvents(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                map(Log::getEvent).collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getEventsForIP(String ip, Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getIp().equals(ip)).
                map(Log::getEvent).collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getEventsForUser(String user, Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getUser().equals(user)).
                map(Log::getEvent).collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getFailedEvents(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getStatus().equals(Status.FAILED)).
                map(Log::getEvent).collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getErrorEvents(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getStatus().equals(Status.ERROR)).
                map(Log::getEvent).collect(Collectors.toSet());
    }

    @Override
    public int getNumberOfAttemptToSolveTask(int task, Date after, Date before) {
        return (int) logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getEvent().equals(Event.SOLVE_TASK)).
                filter(x -> x.getTask() == task).
                count();
    }

    @Override
    public int getNumberOfSuccessfulAttemptToSolveTask(int task, Date after, Date before) {
        return (int) logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getEvent().equals(Event.DONE_TASK)).
                filter(x -> x.getTask() == task).
                count();
    }

    @Override
    public Map<Integer, Integer> getAllSolvedTasksAndTheirNumber(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getEvent().equals(Event.SOLVE_TASK)).
                collect(Collectors.toMap(Log::getTask, log -> 1, Integer::sum));
    }

    @Override
    public Map<Integer, Integer> getAllDoneTasksAndTheirNumber(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getEvent().equals(Event.DONE_TASK)).
                collect(Collectors.toMap(Log::getTask, log -> 1, Integer::sum));
    }

    @Override
    public int getNumberOfUniqueIPs(Date after, Date before) {
        return getUniqueIPs(after, before).size();
    }

    @Override
    public Set<String> getUniqueIPs(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                map(Log::getIp).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getIPsForUser(String user, Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getUser().equals(user)).
                map(Log::getIp).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getIPsForEvent(Event event, Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getEvent().equals(event)).
                map(Log::getIp).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getIPsForStatus(Status status, Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getStatus().equals(status)).
                map(Log::getIp).collect(Collectors.toSet());
    }
    @Override
    public Set<String> getAllUsers() {
        return logs.stream().map(Log::getUser).collect(Collectors.toSet());
    }

    @Override
    public int getNumberOfUsers(Date after, Date before) {
        return getAllUsers().size();
    }

    @Override
    public int getNumberOfUserEvents(String user, Date after, Date before) {
        return (int) logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(l -> l.getUser().equals(user)).
                filter(l -> isDateInRange(l.getLogDate(), after, before)).
                count();
    }

    @Override
    public Set<String> getUsersForIP(String ip, Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getIp().equals(ip)).
                map(Log::getUser).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getLoggedUsers(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getEvent().equals(Event.LOGIN)).
                map(Log::getUser).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getDownloadedPluginUsers(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getEvent().equals(Event.DOWNLOAD_PLUGIN)).
                map(Log::getUser).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getWroteMessageUsers(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getEvent().equals(Event.WRITE_MESSAGE)).
                map(Log::getUser).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getSolvedTaskUsers(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getEvent().equals(Event.SOLVE_TASK)).
                map(Log::getUser).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getSolvedTaskUsers(Date after, Date before, int task) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getEvent().equals(Event.SOLVE_TASK)).
                filter(x -> x.getTask() == task).map(Log::getUser).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getDoneTaskUsers(Date after, Date before) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getEvent().equals(Event.DONE_TASK)).
                map(Log::getUser).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getDoneTaskUsers(Date after, Date before, int task) {
        return logs.stream().filter(x -> isDateInRange(x.getLogDate(), after, before)).
                filter(x -> x.getEvent().equals(Event.DONE_TASK)).
                filter(x -> x.getTask() == task).
                map(Log::getUser).collect(Collectors.toSet());
    }
}
