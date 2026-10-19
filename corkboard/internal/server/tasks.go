package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"corkboard/internal/store"
)

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.TaskFilter{
		State:    q.Get("state"),
		Owner:    q.Get("owner"),
		HostID:   nil,
		Priority: 0,
	}
	if f.State != "" && !store.TaskStateValid(f.State) {
		writeErr(w, http.StatusBadRequest, "invalid_request", "invalid state filter")
		return
	}
	if p := q.Get("priority"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 5 {
			writeErr(w, http.StatusBadRequest, "invalid_request", "invalid priority filter")
			return
		}
		f.Priority = n
	}
	if host := q.Get("host"); host != "" {
		d, err := s.store.GetHost(r.Context(), host)
		if errors.Is(err, store.ErrUnknownHost) {
			writeErr(w, http.StatusBadRequest, "invalid_request", "unknown host")
			return
		}
		if err != nil {
			s.log.Error("list tasks", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal_error", "lookup failed")
			return
		}
		id := d.Host.ID
		f.HostID = &id
	}
	f.HideLocked = f.HostID == nil
	tasks, err := s.store.ListTasks(r.Context(), f)
	if err != nil {
		s.log.Error("list tasks", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "query failed")
		return
	}
	writeJSON(w, http.StatusOK, tasks)
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP       string   `json:"ip"`
		Title    string   `json:"title"`
		Body     string   `json:"body"`
		Commands []string `json:"commands"`
		Priority int      `json:"priority"`
		Port     int      `json:"port"`
		Proto    string   `json:"proto"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if body.IP == "" || body.Title == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "ip and title are required")
		return
	}
	if body.Priority < 0 || body.Priority > 5 {
		writeErr(w, http.StatusBadRequest, "invalid_request", "priority must be 1-5")
		return
	}
	d, err := s.store.GetHost(r.Context(), body.IP)
	if errors.Is(err, store.ErrUnknownHost) {
		writeErr(w, http.StatusNotFound, "unknown_host", body.IP)
		return
	}
	if err != nil {
		s.log.Error("create task", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "lookup failed")
		return
	}
	hostID := d.Host.ID
	var serviceID *int64
	if body.Port != 0 {
		if body.Proto == "" {
			body.Proto = "tcp"
		}
		for _, sv := range d.Services {
			if sv.Port == body.Port && sv.Proto == body.Proto {
				serviceID = &sv.ID
			}
		}
		if serviceID == nil {
			writeErr(w, http.StatusNotFound, "unknown_service", fmt.Sprintf("%s has no %d/%s service", body.IP, body.Port, body.Proto))
			return
		}
	}
	user := userFrom(r.Context())
	id, created, err := s.store.CreateTask(r.Context(), user, store.NewTask{
		DedupeKey: store.ManualTaskKey(hostID, serviceID, body.Title),
		HostID:    &hostID,
		ServiceID: serviceID,
		Title:     body.Title,
		Body:      body.Body,
		Commands:  body.Commands,
		Priority:  body.Priority,
	})
	if err != nil {
		s.log.Error("create task", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "insert failed")
		return
	}
	t, err := s.store.GetTask(r.Context(), id)
	if err != nil {
		s.log.Error("create task readback", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "read failed")
		return
	}
	code := http.StatusCreated
	if !created {
		code = http.StatusOK
	}
	writeJSON(w, code, t)
}

func (s *Server) handlePatchTask(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid_request", "task id must be a positive integer")
		return
	}
	var body struct {
		State string `json:"state"`
		Note  string `json:"note"`
		Steal bool   `json:"steal"`
		Owner string `json:"owner"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if body.State == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "state is required")
		return
	}
	user := userFrom(r.Context())
	ctx := r.Context()
	switch body.State {
	case "claimed":
		if err := s.store.ClaimTask(ctx, id, user, body.Steal); err != nil {
			s.taskErr(w, err)
			return
		}
	case "open":
		if err := s.store.ReleaseTask(ctx, id, user); err != nil {
			s.taskErr(w, err)
			return
		}
	case "done", "blocked":
		if err := s.store.SetTaskState(ctx, id, user, body.State, body.Note); err != nil {
			s.taskErr(w, err)
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "invalid_request", "state must be claimed, open, done, or blocked")
		return
	}
	t, err := s.store.GetTask(ctx, id)
	if err != nil {
		s.log.Error("patch task readback", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "read failed")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) taskErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrUnknownTask):
		writeErr(w, http.StatusNotFound, "unknown_task", err.Error())
	case errors.Is(err, store.ErrTaskClosed):
		writeErr(w, http.StatusConflict, "task_closed", err.Error())
	case errors.Is(err, store.ErrAlreadyClaimed):
		writeErr(w, http.StatusConflict, "already_claimed", err.Error())
	case errors.Is(err, store.ErrHostLocked):
		writeErr(w, http.StatusConflict, "host_locked", err.Error())
	case errors.Is(err, store.ErrNotOwner):
		writeErr(w, http.StatusForbidden, "not_owner", err.Error())
	case errors.Is(err, store.ErrInvalidInput):
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		s.log.Error("task operation", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "operation failed")
	}
}
