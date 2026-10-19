package store

import (
	"context"
	"database/sql"

	"corkboard/internal/coverage"
	"corkboard/internal/model"
)

const httpServiceCond = `(s.proto = 'tcp' AND s.state IN ('open','open|filtered')
	AND (s.port IN (80, 443, 8080, 8443)
	     OR lower(s.name) LIKE 'http%'
	     OR lower(COALESCE(s.product, '')) LIKE '%http%'))`

func (s *Store) Matrix(ctx context.Context) ([]model.HostCoverage, error) {
	hrows, err := s.db.Read.QueryContext(ctx,
		`SELECT id, ip, scope_zone FROM hosts WHERE scope_zone != 'out' ORDER BY ip_sort`)
	if err != nil {
		return nil, err
	}
	defer hrows.Close()
	type hostRow struct {
		id   int64
		ip   string
		zone string
	}
	var hosts []hostRow
	for hrows.Next() {
		var h hostRow
		if err := hrows.Scan(&h.id, &h.ip, &h.zone); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	if err := hrows.Err(); err != nil {
		return nil, err
	}

	type cellKey struct {
		hostID int64
		stage  string
	}
	latest := map[cellKey]struct {
		cell  model.CoverageCell
		runID int64
	}{}
	crows, err := s.db.Read.QueryContext(ctx,
		`SELECT rc.host_id, rc.stage, r.uploaded_by, COALESCE(r.finished_at,r.uploaded_at), rc.run_id, rc.status
		 FROM run_coverage rc JOIN runs r ON r.id = rc.run_id`)
	if err != nil {
		return nil, err
	}
	defer crows.Close()
	for crows.Next() {
		var (
			hostID, runID int64
			stage         string
			cell          model.CoverageCell
		)
		if err := crows.Scan(&hostID, &stage, &cell.Actor, &cell.At, &runID, &cell.Status); err != nil {
			return nil, err
		}
		cell.Done = cell.Status == "completed" || cell.Status == "not_applicable"
		k := cellKey{hostID, stage}
		old, ok := latest[k]
		if !ok || cell.At > old.cell.At || (cell.At == old.cell.At && runID > old.runID) {
			latest[k] = struct {
				cell  model.CoverageCell
				runID int64
			}{cell, runID}
		}
	}
	if err := crows.Err(); err != nil {
		return nil, err
	}

	matrix := make([]model.HostCoverage, 0, len(hosts))
	for _, h := range hosts {
		stages := make(map[string]model.CoverageCell, len(coverage.Stages()))
		for _, st := range coverage.Stages() {
			var cell model.CoverageCell
			if st == coverage.StageWebShots {
				cell, err = s.webShotsCell(ctx, h.id)
				if err != nil {
					return nil, err
				}
			} else if entry, ok := latest[cellKey{h.id, st}]; ok {
				cell = entry.cell
			}
			stages[st] = cell
		}
		matrix = append(matrix, model.HostCoverage{
			HostID: h.id,
			IP:     h.ip,
			Zone:   h.zone,
			Stages: stages,
		})
	}
	return matrix, nil
}

func (s *Store) webShotsCell(ctx context.Context, hostID int64) (model.CoverageCell, error) {
	var nHTTP, nCovered int
	err := s.db.Read.QueryRowContext(ctx,
		`SELECT COUNT(*),
		        COALESCE(SUM(CASE WHEN EXISTS (
		           SELECT 1 FROM web_results w
		           WHERE w.service_id = s.id AND w.failed = 0
		         ) THEN 1 ELSE 0 END), 0)
		 FROM services s
		 WHERE s.host_id = ? AND `+httpServiceCond,
		hostID).Scan(&nHTTP, &nCovered)
	if err != nil {
		return model.CoverageCell{}, err
	}
	if nHTTP > 0 && nCovered != nHTTP {
		return model.CoverageCell{}, nil
	}
	if nHTTP == 0 {
		return model.CoverageCell{Done: true, Status: "not_applicable"}, nil
	}
	var at sql.NullInt64
	var actor sql.NullString
	err = s.db.Read.QueryRowContext(ctx,
		`SELECT w.probed_at, r.uploaded_by
		 FROM web_results w JOIN runs r ON r.id = w.run_id
		 WHERE w.host_id = ? AND w.failed = 0
		 ORDER BY w.probed_at DESC, w.id DESC LIMIT 1`, hostID).Scan(&at, &actor)
	if err != nil && err != sql.ErrNoRows {
		return model.CoverageCell{}, err
	}
	return model.CoverageCell{Done: true, At: at.Int64, Actor: actor.String}, nil
}
